use crate::config::{Candidate, Config, Health, Probe, Route};
use crate::policy::{Action, Policy};

pub fn run_demo() {
    let mut primary = Candidate::new("primary", vec![Probe::new("192.0.2.10", 443)]);
    primary.local_pref = 200;
    let backup = Candidate::new("backup", vec![Probe::new("192.0.2.20", 443)]);
    let route = Route::new("10.20.0.0/16", vec![primary, backup]);
    let mut config = Config::new(vec![route.clone()]);
    config.health = Health { failures: 3, successes: 2, failback_delay: 5.0, ..Health::default() };
    let h = config.health.clone();
    let mut policy = Policy::new(config, 0.0);
    let mut last: Option<(Action, Vec<String>)> = None;
    println!("Simulation: primary fails at t=4s, recovers at t=10s; failback hold-down is 5s.");
    for tick in 0..18u32 {
        let now = f64::from(tick);
        for c in &route.candidates {
            let ok = c.id != "primary" || !(4..10).contains(&tick);
            policy.path(&route.key(), &c.id).observe(ok, now, &h, None, None);
        }
        let decision = policy.select(&route, now);
        policy.commit(&route, &decision);
        let current = (decision.action, decision.paths.clone());
        if last.as_ref() != Some(&current) {
            let paths = if decision.paths.is_empty() { "-".to_string() } else { decision.paths.join(",") };
            println!("t={tick:2}s  {:8}  {paths:12}  {}", decision.action.to_string(), decision.reason);
            last = Some(current);
        }
    }
}
