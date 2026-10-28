//! Learned routes, endpoint expiry, deterministic selection and recovery hold-down.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::config::ServerConfig;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnedRoute {
    pub prefix: String,
    pub peer: String,
    pub endpoint: String,
    pub eni: String,
    pub next_hop: String,
    pub as_path: Vec<u32>,
    pub med: u32,
    pub local_pref: u32,
}

pub type RouteKey = (String, String, String);

impl LearnedRoute {
    pub fn key(&self) -> RouteKey {
        (self.prefix.clone(), self.peer.clone(), self.next_hop.clone())
    }

    pub fn rank(&self) -> (Reverse<u32>, usize, u32) {
        (Reverse(self.local_pref), self.as_path.len(), self.med)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct PeerState {
    pub up: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub bgp: BTreeMap<u8, bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bfd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl PeerState {
    pub fn up(up: bool) -> Self {
        PeerState { up, ..Default::default() }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Rejected {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    pub peer: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub routes: Vec<LearnedRoute>,
    pub peers: BTreeMap<String, PeerState>,
    pub rejected: Vec<Rejected>,
}

pub type Fib = BTreeMap<String, LearnedRoute>;

pub struct Rib {
    pub config: ServerConfig,
    pub snapshots: BTreeMap<String, (f64, Snapshot)>,
    pub since: HashMap<RouteKey, f64>,
    pub selected: Fib,
    pub persisted: bool,
    pub resume_at: Option<f64>,
}

impl Rib {
    pub fn new(config: ServerConfig) -> Self {
        Rib { config, snapshots: BTreeMap::new(), since: HashMap::new(), selected: Fib::new(), persisted: false, resume_at: None }
    }

    pub fn update(&mut self, endpoint: &str, snapshot: Snapshot, now: f64) {
        let old_keys: HashSet<RouteKey> = match self.snapshots.get(endpoint) {
            Some((at, old)) if now - at < self.config.stale_after => old.routes.iter().map(LearnedRoute::key).collect(),
            _ => HashSet::new(),
        };
        let new_keys: HashSet<RouteKey> = snapshot.routes.iter().map(LearnedRoute::key).collect();
        for key in old_keys.difference(&new_keys) {
            self.since.remove(key);
        }
        for key in new_keys.difference(&old_keys) {
            self.since.insert(key.clone(), now);
        }
        self.snapshots.insert(endpoint.to_string(), (now, snapshot));
    }

    pub fn fresh(&mut self, now: f64) -> BTreeMap<String, Snapshot> {
        let mut result = BTreeMap::new();
        for (eid, (at, snapshot)) in &self.snapshots {
            if now - at < self.config.stale_after {
                result.insert(eid.clone(), snapshot.clone());
            } else {
                for route in &snapshot.routes {
                    self.since.remove(&route.key());
                }
            }
        }
        result
    }

    pub fn select(&mut self, now: f64) -> Fib {
        let snapshots = self.fresh(now);
        let any_up = snapshots.values().flat_map(|s| s.peers.values()).any(|p| p.up);
        if self.config.persist_routes {
            if !any_up {
                self.persisted = !self.selected.is_empty();
                self.resume_at = None;
                return self.selected.clone();
            }
            if self.persisted {
                let resume_at = *self.resume_at.get_or_insert(now + self.config.persist_duration);
                if now < resume_at {
                    return self.selected.clone();
                }
                self.persisted = false;
                self.resume_at = None;
            }
        }
        let mut choices: BTreeMap<&str, Vec<&LearnedRoute>> = BTreeMap::new();
        for route in snapshots.values().flat_map(|s| &s.routes) {
            choices.entry(&route.prefix).or_default().push(route);
        }
        let mut selected = Fib::new();
        for (prefix, mut candidates) in choices {
            let current = self.selected.get(prefix).map(LearnedRoute::key);
            if let Some(current_key) = current.as_ref().filter(|k| candidates.iter().any(|r| &r.key() == *k)) {
                candidates.retain(|r| {
                    &r.key() == current_key
                        || now - self.since.get(&r.key()).copied().unwrap_or(now) >= self.config.failback_delay
                });
            }
            candidates.sort_by(|a, b| {
                let order = |r: &LearnedRoute| (r.rank(), Some(r.key()) != current, r.peer.clone(), r.next_hop.clone());
                order(a).cmp(&order(b))
            });
            selected.insert(prefix.to_string(), candidates[0].clone());
        }
        self.selected = selected.clone();
        selected
    }

    pub fn view(&mut self, now: f64) -> Value {
        let fresh = self.fresh(now);
        let endpoints: serde_json::Map<String, Value> = self
            .config
            .endpoints
            .iter()
            .map(|e| {
                let age = self.snapshots.get(&e.id).map(|(at, _)| now - at);
                (e.id.clone(), json!({"fresh": fresh.contains_key(&e.id), "age": age}))
            })
            .collect();
        let peers: serde_json::Map<String, Value> = self
            .config
            .peers
            .iter()
            .map(|p| {
                let state = match fresh.get(&p.endpoint) {
                    Some(s) => s.peers.get(&p.id).map_or_else(
                        || json!({"up": false, "reason": "missing peer"}),
                        |state| serde_json::to_value(state).unwrap_or_default(),
                    ),
                    None => json!({"up": false, "reason": "endpoint data expired"}),
                };
                (p.id.clone(), state)
            })
            .collect();
        json!({
            "persisted": self.persisted,
            "resume_in": self.resume_at.map(|r| (r - now).max(0.0)),
            "endpoints": endpoints,
            "peers": peers,
            "rib": fresh.values().flat_map(|s| &s.routes).collect::<Vec<_>>(),
            "fib": self.selected,
            "rejected": fresh.values().flat_map(|s| &s.rejected).collect::<Vec<_>>(),
        })
    }
}
