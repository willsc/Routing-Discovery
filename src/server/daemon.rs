use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use super::config::{Endpoint, ServerConfig};
use super::frr::Source;
use super::journal::Journal;
use super::propagation::Propagator;
use super::rib::{Fib, Rib};
use crate::clock::monotonic;
use crate::daemon::{pause, supervise, MapOk};
use crate::error::Result;
use crate::http::{self, StatusSource};
use crate::supervision::notify;

pub struct RouteServer {
    pub config: ServerConfig,
    pub journal: Arc<Mutex<Journal>>,
    pub apply: bool,
    source: Arc<dyn Source>,
    pub rib: Mutex<Rib>,
    pub propagator: Propagator,
    pub stop: CancellationToken,
    pub errors: Mutex<std::collections::BTreeMap<String, String>>,
    started: f64,
    last_loop: Mutex<f64>,
    attempted: Mutex<std::collections::BTreeSet<String>>,
    generation: AtomicU64,
    desired: Mutex<Fib>,
    reconciled_generation: AtomicI64,
    pub local_addr: Mutex<Option<SocketAddr>>,
}

impl RouteServer {
    pub fn new(
        config: ServerConfig,
        journal: Arc<Mutex<Journal>>,
        source: Arc<dyn Source>,
        propagator: Propagator,
    ) -> Result<Self> {
        let mut rib = Rib::new(config.clone());
        rib.selected = journal.lock().unwrap().load_fib(&config)?;
        let started = monotonic();
        Ok(RouteServer {
            apply: propagator.apply,
            config,
            journal,
            source,
            rib: Mutex::new(rib),
            propagator,
            stop: CancellationToken::new(),
            errors: Mutex::new(Default::default()),
            started,
            last_loop: Mutex::new(started),
            attempted: Mutex::new(Default::default()),
            generation: AtomicU64::new(0),
            desired: Mutex::new(Fib::new()),
            reconciled_generation: AtomicI64::new(-1),
            local_addr: Mutex::new(None),
        })
    }

    async fn endpoint_loop(self: Arc<Self>, endpoint: Endpoint) {
        while !self.stop.is_cancelled() {
            match self.source.read(&endpoint).await {
                Ok(snapshot) => {
                    self.rib.lock().unwrap().update(&endpoint.id, snapshot, monotonic());
                    self.errors.lock().unwrap().remove(&endpoint.id);
                }
                Err(e) => {
                    self.errors.lock().unwrap().insert(endpoint.id.clone(), e.to_string());
                    error!("endpoint_error endpoint={} error={e}", endpoint.id);
                }
            }
            self.attempted.lock().unwrap().insert(endpoint.id.clone());
            pause(&self.stop, self.config.poll_interval).await;
        }
    }

    /// Recompute the FIB; a change bumps the generation, invalidating any in-flight AWS pass.
    pub fn selection(&self) -> Result<bool> {
        let attempted = self.attempted.lock().unwrap().len();
        if attempted < self.config.endpoints.len() && monotonic() - self.started < self.config.stale_after {
            return Ok(false);
        }
        let (selected, persisted) = {
            let mut rib = self.rib.lock().unwrap();
            let selected = rib.select(monotonic());
            (selected, rib.persisted)
        };
        let mut desired = self.desired.lock().unwrap();
        if selected != *desired {
            self.journal.lock().unwrap().save_fib(&selected)?;
            let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
            info!("fib_change generation={generation} prefixes={} persisted={persisted}", selected.len());
            *desired = selected;
        }
        Ok(true)
    }

    async fn control_loop(self: Arc<Self>) {
        let mut delay = self.config.reconcile_interval;
        while !self.stop.is_cancelled() {
            let pass = async {
                if !self.selection()? {
                    return Ok(());
                }
                let generation = self.generation.load(Ordering::SeqCst);
                let fib = self.desired.lock().unwrap().clone();
                let guard = || generation == self.generation.load(Ordering::SeqCst) && !self.stop.is_cancelled();
                let converged = self.propagator.reconcile(&fib, &guard).await?;
                if converged && generation == self.generation.load(Ordering::SeqCst) {
                    self.reconciled_generation.store(generation as i64, Ordering::SeqCst);
                }
                delay = if converged { self.config.reconcile_interval } else { (delay * 2.0).min(30.0) };
                Ok::<_, crate::Error>(())
            };
            match pass.await {
                Ok(()) => {
                    self.errors.lock().unwrap().remove("propagation");
                }
                Err(e) => {
                    self.errors.lock().unwrap().insert("propagation".into(), e.to_string());
                    error!("propagation_error error={e}");
                    delay = (delay * 2.0).min(30.0);
                }
            }
            pause(&self.stop, delay * (0.9 + fastrand::f64() * 0.2)).await;
        }
    }

    async fn heartbeat(self: Arc<Self>) -> Result<()> {
        while !self.stop.is_cancelled() {
            *self.last_loop.lock().unwrap() = monotonic();
            // Invalidate slow AWS passes when BGP changes or observations expire.
            self.selection()?;
            notify("WATCHDOG=1");
            pause(&self.stop, self.config.poll_interval.min(0.5)).await;
        }
        Ok(())
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        self.propagator.verify_targets().await?;
        let listener = TcpListener::bind((self.config.listen, self.config.port)).await?;
        *self.local_addr.lock().unwrap() = Some(listener.local_addr()?);
        notify("READY=1");
        let mut tasks: JoinSet<Result<()>> = JoinSet::new();
        let source: Arc<dyn StatusSource> = self.clone();
        tasks.spawn(http::serve(listener, source, self.stop.clone()).map_ok());
        tasks.spawn(self.clone().heartbeat());
        tasks.spawn(self.clone().control_loop().map_ok());
        for endpoint in &self.config.endpoints {
            tasks.spawn(self.clone().endpoint_loop(endpoint.clone()).map_ok());
        }
        let outcome = supervise(&mut tasks, &self.stop).await;
        while tasks.join_next().await.is_some() {}
        notify("STOPPING=1");
        let selected = self.rib.lock().unwrap().selected.clone();
        let saved = self.journal.lock().unwrap().save_fib(&selected);
        info!("route server stopped; VPC routes retained for supervised restart");
        outcome.and(saved)
    }
}

impl StatusSource for RouteServer {
    fn snapshot(&self) -> Value {
        let now = monotonic();
        let (view, persisted) = {
            let mut rib = self.rib.lock().unwrap();
            (rib.view(now), rib.persisted)
        };
        let propagations = self.propagator.status.lock().unwrap().clone();
        let errors = self.errors.lock().unwrap().clone();
        let any_peer = view["peers"].as_object().is_some_and(|p| p.values().any(|s| s["up"] == true));
        let endpoints_fresh = view["endpoints"].as_object().is_some_and(|e| e.values().all(|s| s["fresh"] == true));
        let generation = self.generation.load(Ordering::SeqCst);
        let ready = any_peer
            && !persisted
            && errors.is_empty()
            && endpoints_fresh
            && self.reconciled_generation.load(Ordering::SeqCst) == generation as i64
            && !propagations.is_empty()
            && propagations.values().all(|p| p.converged);
        let mut snapshot = json!({
            "mode": if self.apply { "apply" } else { "dry-run" },
            "backend": "route-server",
            "id": self.config.id,
            "vpc": self.config.vpc_id,
            "live": now - *self.last_loop.lock().unwrap() < 5.0,
            "ready": ready,
            "generation": generation,
            "source_errors": errors,
        });
        if let (Some(target), Value::Object(fields)) = (snapshot.as_object_mut(), view) {
            target.extend(fields);
            target.insert("propagations".into(), serde_json::to_value(propagations).unwrap_or_default());
        }
        snapshot
    }

    fn metrics(&self) -> String {
        let status = self.snapshot();
        let count = |key: &str| status[key].as_array().map_or_else(|| status[key].as_object().map_or(0, |o| o.len()), Vec::len);
        let flag = |v: &Value| u8::from(v.as_bool().unwrap_or(false));
        let mut lines = vec![
            format!("route_server_ready {}", flag(&status["ready"])),
            format!("route_server_rib_paths {}", count("rib")),
            format!("route_server_fib_prefixes {}", count("fib")),
            format!("route_server_persisted {}", flag(&status["persisted"])),
            format!("route_server_changes_total {}", self.propagator.changes.load(Ordering::Relaxed)),
            format!("route_server_write_errors_total {}", self.propagator.failures.load(Ordering::Relaxed)),
        ];
        for (peer, state) in status["peers"].as_object().into_iter().flatten() {
            lines.push(format!("route_server_peer_up{{peer=\"{peer}\"}} {}", flag(&state["up"])));
        }
        for (table, state) in status["propagations"].as_object().into_iter().flatten() {
            lines.push(format!("route_server_propagation_converged{{table=\"{table}\"}} {}", flag(&state["converged"])));
        }
        lines.join("\n") + "\n"
    }
}
