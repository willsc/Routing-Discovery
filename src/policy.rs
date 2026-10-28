//! Deterministic routing policy, independent of clocks, sockets and route writers.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::config::{AllDown, Candidate, Config, Health, Route};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PathState {
    #[default]
    Unknown,
    Up,
    Down,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PathHealth {
    pub state: PathState,
    pub good: u32,
    pub bad: u32,
    pub last_sample: Option<f64>,
    pub up_since: Option<f64>,
    pub penalty: f64,
    pub penalty_at: Option<f64>,
    pub suppressed_since: Option<f64>,
    pub last_error: Option<String>,
    pub latency_ms: Option<f64>,
}

impl PathHealth {
    pub fn decay(&mut self, now: f64, h: &Health) {
        if let Some(at) = self.penalty_at {
            self.penalty *= (-(now - at).max(0.0) / h.dampening_half_life).exp2();
        }
        self.penalty_at = Some(now);
        if let Some(since) = self.suppressed_since {
            if self.penalty < h.dampening_reuse || now - since >= h.dampening_max {
                self.suppressed_since = None;
                self.penalty = self.penalty.min(h.dampening_reuse);
            }
        }
    }

    fn down(&mut self, now: f64, h: &Health) {
        if self.state == PathState::Up {
            self.penalty = (self.penalty + h.dampening_penalty).min(h.dampening_suppress * 4.0);
            if self.penalty >= h.dampening_suppress && self.suppressed_since.is_none() {
                self.suppressed_since = Some(now);
            }
        }
        self.state = PathState::Down;
        self.up_since = None;
    }

    fn stale(&self, now: f64, h: &Health) -> bool {
        self.last_sample.is_some_and(|last| now - last >= h.stale_after)
    }

    pub fn observe(&mut self, success: bool, now: f64, h: &Health, error: Option<String>, latency_ms: Option<f64>) {
        self.decay(now, h);
        // A scheduler/probe gap breaks consecutive successes and invalidates an old UP.
        if self.stale(now, h) {
            self.down(now, h);
            self.good = 0;
            self.bad = 0;
        }
        self.last_sample = Some(now);
        self.last_error = error;
        self.latency_ms = latency_ms;
        if success {
            self.bad = 0;
            self.good = (self.good + 1).min(h.successes);
            if self.good >= h.successes && self.state != PathState::Up {
                self.state = PathState::Up;
                self.up_since = Some(now);
            }
        } else {
            self.good = 0;
            self.bad = (self.bad + 1).min(h.failures);
            if self.bad >= h.failures {
                self.down(now, h);
            }
        }
    }

    pub fn eligible(&mut self, now: f64, h: &Health) -> bool {
        self.decay(now, h);
        if self.stale(now, h) {
            self.down(now, h);
            self.good = 0;
        }
        self.state == PathState::Up && self.suppressed_since.is_none()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Hold,
    Route,
    Withdraw,
    Unreachable,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Action::Hold => "hold",
            Action::Route => "route",
            Action::Withdraw => "withdraw",
            Action::Unreachable => "unreachable",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub action: Action,
    pub paths: Vec<String>,
    pub reason: String,
}

impl Decision {
    pub fn new(action: Action, reason: &str) -> Self {
        Decision { action, paths: Vec::new(), reason: reason.into() }
    }

    pub fn route<S: AsRef<str>>(paths: &[S]) -> Self {
        Decision { action: Action::Route, paths: paths.iter().map(|p| p.as_ref().to_string()).collect(), reason: String::new() }
    }
}

pub type PathKey = (String, String);

pub struct Policy {
    pub config: Config,
    pub started: f64,
    pub health: HashMap<PathKey, PathHealth>,
    pub installed: HashMap<String, Vec<String>>,
}

impl Policy {
    pub fn new(config: Config, started: f64) -> Self {
        let health = config
            .routes
            .iter()
            .flat_map(|r| r.candidates.iter().map(move |c| ((r.key(), c.id.clone()), PathHealth::default())))
            .collect();
        let installed = config.routes.iter().map(|r| (r.key(), Vec::new())).collect();
        Policy { config, started, health, installed }
    }

    pub fn path(&mut self, prefix: &str, id: &str) -> &mut PathHealth {
        self.health.entry((prefix.to_string(), id.to_string())).or_default()
    }

    fn admissible(&self, c: &Candidate) -> bool {
        c.enabled && !c.as_path.contains(&self.config.local_asn)
    }

    pub fn select(&mut self, route: &Route, now: f64) -> Decision {
        let h = self.config.health.clone();
        let prefix = route.key();
        let active: HashSet<String> = self.installed.get(&prefix).cloned().unwrap_or_default().into_iter().collect();
        let mut eligible: Vec<&Candidate> = Vec::new();
        for c in &route.candidates {
            let healthy = self.path(&prefix, &c.id).eligible(now, &h);
            if healthy && self.admissible(c) {
                eligible.push(c);
            }
        }
        if eligible.is_empty() {
            let pending = route
                .candidates
                .iter()
                .filter(|c| self.admissible(c))
                .any(|c| self.health.get(&(prefix.clone(), c.id.clone())).is_none_or(|s| s.state == PathState::Unknown));
            if pending && now - self.started < h.stale_after {
                return Decision::new(Action::Hold, "initial health assessment");
            }
            let action = match route.all_down {
                AllDown::Retain => Action::Hold,
                AllDown::Withdraw => Action::Withdraw,
                AllDown::Unreachable => Action::Unreachable,
            };
            return Decision::new(action, "no eligible path");
        }
        if eligible.iter().any(|c| active.contains(&c.id)) {
            if !route.preempt {
                eligible.retain(|c| active.contains(&c.id));
            } else {
                // Hold-down only delays elective preemption, never emergency failover.
                eligible.retain(|c| {
                    active.contains(&c.id)
                        || self.health[&(prefix.clone(), c.id.clone())].up_since.is_some_and(|up| now - up >= h.failback_delay)
                });
            }
        }
        eligible.sort_by(|a, b| (a.rank(), !active.contains(&a.id), &a.id).cmp(&(b.rank(), !active.contains(&b.id), &b.id)));
        let best = eligible[0].rank();
        let mut paths: Vec<String> =
            eligible.iter().filter(|c| c.rank() == best).take(route.max_paths).map(|c| c.id.clone()).collect();
        paths.sort();
        Decision { action: Action::Route, paths, reason: "best eligible policy rank".into() }
    }

    pub fn commit(&mut self, route: &Route, decision: &Decision) {
        if decision.action != Action::Hold {
            self.installed.insert(route.key(), decision.paths.clone());
        }
    }
}
