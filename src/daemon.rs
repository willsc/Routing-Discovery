//! Probe loops, per-prefix reconcilers, heartbeat and the status endpoint for host routing.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::backends::{Backend, Observed, PathValidator, ProbePathValidator};
use crate::clock::monotonic;
use crate::config::{BackendKind, Config, Route};
use crate::error::{Error, Result};
use crate::http::{self, StatusSource};
use crate::policy::{Action, Decision, Policy};
use crate::probes::{Prober, TcpProber};
use crate::state::StateStore;
use crate::supervision::notify;

#[derive(Clone, Debug, Default, Serialize)]
pub struct RouteStatus {
    pub converged: bool,
    pub error: Option<String>,
    pub decision: Option<Decision>,
    pub observed: Option<Observed>,
}

pub struct Daemon {
    pub config: Config,
    pub backend: Arc<dyn Backend>,
    pub store: Option<StateStore>,
    pub apply: bool,
    pub prober: Arc<dyn Prober>,
    pub validator: Arc<dyn PathValidator>,
    pub policy: Mutex<Policy>,
    pub stop: CancellationToken,
    write_lock: tokio::sync::Mutex<()>,
    pub route_status: Mutex<BTreeMap<String, RouteStatus>>,
    pub probe_path_errors: Mutex<BTreeMap<(String, String), String>>,
    last_loop: Mutex<f64>,
    changes: AtomicU64,
    errors: AtomicU64,
    /// The bound status address, once `run` is listening (port 0 picks a free port).
    pub local_addr: Mutex<Option<SocketAddr>>,
}

/// Wait for `delay` seconds or until stop is requested.
pub async fn pause(stop: &CancellationToken, delay: f64) {
    tokio::select! {
        _ = stop.cancelled() => {}
        _ = tokio::time::sleep(Duration::from_secs_f64(delay.max(0.001))) => {}
    }
}

fn jitter() -> f64 {
    0.9 + fastrand::f64() * 0.2
}

impl Daemon {
    pub fn new(config: Config, backend: Arc<dyn Backend>) -> Self {
        let route_status = config.routes.iter().map(|r| (r.key(), RouteStatus::default())).collect();
        Daemon {
            policy: Mutex::new(Policy::new(config.clone(), monotonic())),
            config,
            backend,
            store: None,
            apply: false,
            prober: Arc::new(TcpProber),
            validator: Arc::new(ProbePathValidator::default()),
            stop: CancellationToken::new(),
            write_lock: tokio::sync::Mutex::new(()),
            route_status: Mutex::new(route_status),
            probe_path_errors: Mutex::new(BTreeMap::new()),
            last_loop: Mutex::new(monotonic()),
            changes: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            local_addr: Mutex::new(None),
        }
    }

    pub fn with_store(mut self, store: StateStore) -> Self {
        self.store = Some(store);
        self
    }

    pub fn with_apply(mut self, apply: bool) -> Self {
        self.apply = apply;
        self
    }

    pub fn with_prober(mut self, prober: Arc<dyn Prober>) -> Self {
        self.prober = prober;
        self
    }

    pub fn with_validator(mut self, validator: Arc<dyn PathValidator>) -> Self {
        self.validator = validator;
        self
    }

    pub async fn probe_loop(self: Arc<Self>, route: Route, candidate_index: usize) {
        let candidate = route.candidates[candidate_index].clone();
        let key = (route.key(), candidate.id.clone());
        let h = self.config.health.clone();
        let mut deadline = monotonic();
        // Verify pinning on each sample so routing drift cannot falsely revive a path.
        let scoped =
            Config { routes: vec![Route { candidates: vec![candidate.clone()], ..route.clone() }], ..self.config.clone() };
        while !self.stop.is_cancelled() {
            let checked = if self.apply && self.config.backend.kind != BackendKind::Aws {
                self.validator.validate(&scoped).await
            } else {
                Ok(())
            };
            match checked {
                Ok(()) => {
                    self.probe_path_errors.lock().unwrap().remove(&key);
                    let result = self.prober.probe(&candidate, h.timeout).await;
                    self.policy.lock().unwrap().path(&key.0, &key.1).observe(
                        result.ok,
                        monotonic(),
                        &h,
                        result.error,
                        result.latency_ms,
                    );
                }
                Err(e) => {
                    self.probe_path_errors.lock().unwrap().insert(key.clone(), e.to_string());
                    self.policy.lock().unwrap().path(&key.0, &key.1).observe(false, monotonic(), &h, Some(e.to_string()), None);
                    error!("probe_error prefix={} path={} error={e}", key.0, key.1);
                }
            }
            deadline += h.interval;
            let now = monotonic();
            if deadline < now {
                deadline = now + h.interval;
            }
            pause(&self.stop, deadline - now).await;
        }
    }

    pub async fn reconcile_once(&self, route: &Route) -> Result<()> {
        let prefix = route.key();
        let _guard = self.write_lock.lock().await;
        let observed = self.backend.current(route).await?;
        let decision = {
            let mut policy = self.policy.lock().unwrap();
            policy.installed.insert(prefix.clone(), if observed.usable { observed.paths.clone() } else { Vec::new() });
            policy.select(route, monotonic())
        };
        let previous = {
            let mut statuses = self.route_status.lock().unwrap();
            let status = statuses.entry(prefix.clone()).or_default();
            status.observed = Some(observed.clone());
            let previous = status.decision.replace(decision.clone());
            // HOLD intentionally leaves a route in place, even if its target is unhealthy.
            if decision.action == Action::Hold {
                status.converged = false;
                status.error = None;
                return Ok(());
            }
            previous
        };
        if previous.as_ref() != Some(&decision) {
            info!(
                "route_decision prefix={prefix} action={} paths={} reason={}",
                decision.action,
                decision.paths.join(","),
                decision.reason
            );
        }
        let converged = self.backend.apply(route, &decision).await?;
        if converged {
            self.policy.lock().unwrap().commit(route, &decision);
        }
        // Lock order everywhere: policy before route_status, never nested the other way.
        let mut statuses = self.route_status.lock().unwrap();
        let status = statuses.entry(prefix).or_default();
        status.converged = converged;
        status.error = (!converged).then(|| "waiting for backend convergence".into());
        if converged {
            status.observed = Some(Observed { paths: decision.paths.clone(), action: decision.action, usable: true });
            if observed.paths != decision.paths || observed.action != decision.action || !observed.usable {
                self.changes.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    async fn route_loop(self: Arc<Self>, route: Route) {
        let mut failures: i32 = 0;
        while !self.stop.is_cancelled() {
            match self.reconcile_once(&route).await {
                Ok(()) => {
                    let converged = self.route_status.lock().unwrap().get(&route.key()).is_some_and(|s| s.converged);
                    failures = if converged { 0 } else { (failures + 1).min(5) };
                }
                Err(e) => {
                    failures = (failures + 1).min(5);
                    self.errors.fetch_add(1, Ordering::Relaxed);
                    if let Some(status) = self.route_status.lock().unwrap().get_mut(&route.key()) {
                        status.converged = false;
                        status.error = Some(e.to_string());
                    }
                    error!("route_error prefix={} error={e}", route.key());
                }
            }
            let base = self.config.reconcile_interval;
            let delay = if failures > 0 { (base * 2f64.powi(failures)).min(30.0) } else { base };
            pause(&self.stop, delay * jitter()).await;
        }
    }

    async fn heartbeat(self: Arc<Self>) -> Result<()> {
        let mut last_save = f64::NEG_INFINITY;
        while !self.stop.is_cancelled() {
            let now = monotonic();
            *self.last_loop.lock().unwrap() = now;
            notify("WATCHDOG=1");
            if let Some(store) = &self.store {
                if now - last_save >= 5.0 {
                    store.save(&mut self.policy.lock().unwrap(), now)?;
                    last_save = now;
                }
            }
            pause(&self.stop, 0.5).await;
        }
        Ok(())
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        if let Some(store) = &self.store {
            store.restore(&mut self.policy.lock().unwrap(), monotonic())?;
        }
        if self.apply {
            self.validator.validate(&self.config).await?;
        }
        let listener = TcpListener::bind((self.config.listen, self.config.port)).await?;
        *self.local_addr.lock().unwrap() = Some(listener.local_addr()?);
        notify("READY=1");
        let mut tasks: JoinSet<Result<()>> = JoinSet::new();
        let source: Arc<dyn StatusSource> = self.clone();
        tasks.spawn(http::serve(listener, source, self.stop.clone()).map_ok());
        tasks.spawn(self.clone().heartbeat());
        for route in &self.config.routes {
            for index in 0..route.candidates.len() {
                tasks.spawn(self.clone().probe_loop(route.clone(), index).map_ok());
            }
            tasks.spawn(self.clone().route_loop(route.clone()).map_ok());
        }
        let outcome = supervise(&mut tasks, &self.stop).await;
        // Let route writes finish: loops observe stop at their next bounded wait.
        while tasks.join_next().await.is_some() {}
        notify("STOPPING=1");
        let saved = match &self.store {
            Some(store) => store.save(&mut self.policy.lock().unwrap(), monotonic()),
            None => Ok(()),
        };
        if self.apply && self.config.backend.kind == BackendKind::Frr {
            for route in &self.config.routes {
                if let Err(e) = self.backend.apply(route, &Decision::new(Action::Withdraw, "daemon shutdown")).await {
                    error!("failed to withdraw FRR route on shutdown: {}: {e}", route.key());
                }
            }
        }
        info!("stopped; Linux/AWS routes retained; FRR routes withdrawn where possible");
        outcome.and(saved)
    }
}

/// Run until stop is requested or a task fails; a failure stops the rest (like a TaskGroup).
pub async fn supervise(tasks: &mut JoinSet<Result<()>>, stop: &CancellationToken) -> Result<()> {
    loop {
        tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            Some(joined) = tasks.join_next() => {
                let failure = match joined {
                    Ok(Ok(())) => continue,
                    Ok(Err(e)) => e,
                    Err(e) => Error::Backend(format!("task failed: {e}")),
                };
                stop.cancel();
                return Err(failure);
            }
        }
    }
}

pub trait MapOk: std::future::Future<Output = ()> + Sized {
    fn map_ok(self) -> impl std::future::Future<Output = Result<()>> {
        async move {
            self.await;
            Ok(())
        }
    }
}

impl<F: std::future::Future<Output = ()>> MapOk for F {}

impl StatusSource for Daemon {
    fn snapshot(&self) -> Value {
        let now = monotonic();
        let h = &self.config.health;
        let mut policy = self.policy.lock().unwrap();
        let statuses = self.route_status.lock().unwrap();
        let mut routes = serde_json::Map::new();
        let mut ready = true;
        for route in &self.config.routes {
            let prefix = route.key();
            let mut paths = serde_json::Map::new();
            let mut eligible_ids = Vec::new();
            for c in &route.candidates {
                let state = policy.path(&prefix, &c.id);
                let eligible = state.eligible(now, h) && c.enabled && !c.as_path.contains(&self.config.local_asn);
                if eligible {
                    eligible_ids.push(c.id.clone());
                }
                paths.insert(
                    c.id.clone(),
                    json!({
                        "state": state.state,
                        "eligible": eligible,
                        "penalty": (state.penalty * 1000.0).round() / 1000.0,
                        "suppressed": state.suppressed_since.is_some(),
                        "last_error": state.last_error,
                        "latency_ms": state.latency_ms,
                        "sample_age": state.last_sample.map(|s| now - s),
                    }),
                );
            }
            let status = statuses.get(&prefix).cloned().unwrap_or_default();
            ready &= status.converged
                && status
                    .decision
                    .as_ref()
                    .is_some_and(|d| d.action == Action::Route && d.paths.iter().all(|p| eligible_ids.contains(p)));
            let mut entry = serde_json::to_value(&status).unwrap_or_default();
            entry["paths"] = Value::Object(paths);
            routes.insert(prefix, entry);
        }
        let live = now - *self.last_loop.lock().unwrap() < h.stale_after.max(5.0);
        json!({
            "mode": if self.apply { "apply" } else { "dry-run" },
            "backend": self.config.backend.kind.as_str(),
            "ready": ready,
            "live": live,
            "changes": self.changes.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "routes": routes,
        })
    }

    fn metrics(&self) -> String {
        let snap = self.snapshot();
        let mut lines = vec![
            format!("route_discovery_ready {}", u8::from(snap["ready"].as_bool().unwrap_or(false))),
            format!("route_discovery_changes_total {}", self.changes.load(Ordering::Relaxed)),
            format!("route_discovery_errors_total {}", self.errors.load(Ordering::Relaxed)),
        ];
        if let Some(routes) = snap["routes"].as_object() {
            for (prefix, route) in routes {
                let selected: Vec<&str> = route["observed"]["paths"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                for (cid, state) in route["paths"].as_object().into_iter().flatten() {
                    let labels = format!("prefix=\"{prefix}\",path=\"{cid}\"");
                    lines.push(format!(
                        "route_discovery_path_up{{{labels}}} {}",
                        u8::from(state["eligible"].as_bool().unwrap_or(false))
                    ));
                    lines.push(format!(
                        "route_discovery_path_selected{{{labels}}} {}",
                        u8::from(selected.contains(&cid.as_str()))
                    ));
                    lines.push(format!("route_discovery_path_penalty{{{labels}}} {}", state["penalty"]));
                }
            }
        }
        lines.join("\n") + "\n"
    }
}
