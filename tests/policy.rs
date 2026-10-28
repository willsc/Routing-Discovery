mod common;

use common::configuration;
use route_discovery::config::{AllDown, BackendKind, Health, Route};
use route_discovery::policy::{Action, Decision, Policy};

struct Harness {
    route: Route,
    policy: Policy,
    health: Health,
}

impl Harness {
    fn new() -> Self {
        let config = configuration(BackendKind::Linux, |h| {
            h.failures = 3;
            h.successes = 2;
            h.failback_delay = 5.0;
        });
        Harness { route: config.routes[0].clone(), health: config.health.clone(), policy: Policy::new(config, 0.0) }
    }

    fn sample_with(&mut self, tick: u32, primary: bool, backup: bool, commit: bool) -> Decision {
        let prefix = self.route.key();
        for (cid, ok) in [("primary", primary), ("backup", backup)] {
            self.policy.path(&prefix, cid).observe(ok, f64::from(tick), &self.health, None, None);
        }
        let decision = self.policy.select(&self.route, f64::from(tick));
        if commit {
            self.policy.commit(&self.route, &decision);
        }
        decision
    }

    fn sample(&mut self, tick: u32, primary: bool, backup: bool) -> Decision {
        self.sample_with(tick, primary, backup, true)
    }
}

#[test]
fn failover_and_delayed_failback() {
    let mut t = Harness::new();
    assert_eq!(t.sample(0, true, true).action, Action::Hold);
    assert_eq!(t.sample(1, true, true).paths, ["primary"]);
    assert_eq!(t.sample(2, false, true).paths, ["primary"]);
    assert_eq!(t.sample(3, false, true).paths, ["primary"]);
    assert_eq!(t.sample(4, false, true).paths, ["backup"]);
    for tick in 5..11 {
        assert_eq!(t.sample(tick, true, true).paths, ["backup"]);
    }
    assert_eq!(t.sample(11, true, true).paths, ["primary"]);
}

#[test]
fn emergency_ignores_preemption_hold() {
    let mut t = Harness::new();
    t.sample(0, false, true);
    t.sample(1, false, true);
    t.sample(2, true, false);
    t.sample(3, true, false);
    assert_eq!(t.sample(4, true, false).paths, ["primary"]);
}

#[test]
fn all_down_and_recovery() {
    let mut t = Harness::new();
    t.sample(0, true, true);
    t.sample(1, true, true);
    for tick in 2..4 {
        t.sample(tick, false, false);
    }
    assert_eq!(t.sample(4, false, false).action, Action::Withdraw);
    t.sample(5, true, true);
    assert_eq!(t.sample(6, true, true).paths, ["primary"]);
}

#[test]
fn all_down_modes_and_startup_grace() {
    let mut t = Harness::new();
    let route = t.route.clone();
    assert_eq!(t.policy.select(&route, 1.0).action, Action::Hold);
    assert_eq!(t.policy.select(&route, 6.0).action, Action::Withdraw);
    assert_eq!(t.policy.select(&Route { all_down: AllDown::Retain, ..route.clone() }, 6.0).action, Action::Hold);
    assert_eq!(t.policy.select(&Route { all_down: AllDown::Unreachable, ..route }, 6.0).action, Action::Unreachable);
}

#[test]
fn stale_health_cannot_keep_route() {
    let mut t = Harness::new();
    t.sample(0, true, true);
    t.sample(1, true, true);
    let route = t.route.clone();
    assert_eq!(t.policy.select(&route, 7.0).action, Action::Withdraw);
    assert_eq!(t.sample(8, true, true).action, Action::Withdraw);
    assert_eq!(t.sample(9, true, true).paths, ["primary"]);
}

#[test]
fn nonpreemptive_route_stays_on_backup() {
    let mut t = Harness::new();
    t.route.preempt = false;
    t.sample(0, false, true);
    t.sample(1, false, true);
    for tick in 2..20 {
        assert_eq!(t.sample(tick, true, true).paths, ["backup"]);
    }
}

#[test]
fn as_loop_and_disabled_paths_are_excluded() {
    let mut t = Harness::new();
    t.route.candidates[0].as_path = vec![65000];
    t.sample(0, true, true);
    assert_eq!(t.sample(1, true, true).paths, ["backup"]);
    t.route.candidates[0].as_path = vec![];
    t.route.candidates[0].enabled = false;
    assert_eq!(t.sample(2, true, true).paths, ["backup"]);
}

#[test]
fn ecmp_and_failed_member_removal() {
    let mut t = Harness::new();
    t.route.max_paths = 2;
    t.route.candidates[1].local_pref = 200;
    t.sample(0, true, true);
    assert_eq!(t.sample(1, true, true).paths, ["backup", "primary"]);
    for tick in 2..4 {
        t.sample(tick, false, true);
    }
    assert_eq!(t.sample(4, false, true).paths, ["backup"]);
}

#[test]
fn rank_localpref_aspath_med_cost() {
    let t = Harness::new();
    let mut a = t.route.candidates[0].clone();
    (a.as_path, a.med, a.cost) = (vec![1], 2, 2);
    for (local_pref, as_path, med, cost) in [(201, vec![], 0, 0), (200, vec![], 0, 0), (200, vec![1], 1, 0), (200, vec![1], 2, 1)]
    {
        let mut b = t.route.candidates[1].clone();
        (b.local_pref, b.as_path, b.med, b.cost) = (local_pref, as_path, med, cost);
        assert!(b.rank() < a.rank());
    }
}

#[test]
fn dampening_decays_and_is_bounded() {
    let mut t = Harness::new();
    let h = Health {
        failures: 1,
        successes: 1,
        dampening_suppress: 1500.0,
        dampening_half_life: 100.0,
        dampening_max: 10.0,
        ..t.health.clone()
    };
    let prefix = t.route.key();
    let state = t.policy.path(&prefix, "primary");
    for (tick, ok) in [(0, true), (1, false), (2, true), (3, false), (4, true)] {
        state.observe(ok, f64::from(tick), &h, None, None);
    }
    assert!(!state.eligible(4.0, &h));
    for tick in 5..14 {
        state.observe(true, f64::from(tick), &h, None, None);
    }
    assert!(state.eligible(13.0, &h));
}

#[test]
fn uncommitted_decision_does_not_change_installed() {
    let mut t = Harness::new();
    t.sample(0, true, true);
    assert_eq!(t.sample_with(1, true, true, false).paths, ["primary"]);
    assert!(t.policy.installed[&t.route.key()].is_empty());
}
