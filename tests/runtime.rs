mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use common::{configuration, linux};
use route_discovery::backends::{Backend, DryRun, PathValidator};
use route_discovery::clock::monotonic;
use route_discovery::config::{BackendKind, Candidate, Config, Probe};
use route_discovery::daemon::Daemon;
use route_discovery::error::{backend_err, Result};
use route_discovery::policy::{Action, Decision, PathState, Policy};
use route_discovery::probes::{candidate_probe, tcp_probe, ProbeResult, Prober};
use route_discovery::state::StateStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[test]
fn single_writer_and_persistent_dampening() {
    let config = linux();
    let directory = tempfile::tempdir().unwrap();
    let mut store = StateStore::new(directory.path());
    store.acquire().unwrap();
    let mut second = StateStore::new(directory.path());
    assert!(second.acquire().is_err());
    let mut policy = Policy::new(config.clone(), 0.0);
    let prefix = config.routes[0].key();
    let state = policy.path(&prefix, "primary");
    (state.penalty, state.penalty_at, state.suppressed_since, state.state) = (3000.0, Some(100.0), Some(99.0), PathState::Up);
    store.save(&mut policy, 100.0).unwrap();
    let mut restored = Policy::new(config, 0.0);
    store.restore(&mut restored, 200.0).unwrap();
    let value = restored.path(&prefix, "primary");
    assert!(value.penalty > 2900.0);
    assert!(value.suppressed_since.is_some());
    assert_eq!(value.state, PathState::Unknown);
    assert!(value.last_sample.is_none());
    store.close();
    second.acquire().unwrap();
}

#[test]
fn corrupt_checkpoint_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("dampening.json"), r#"{"version": 999}"#).unwrap();
    assert!(StateStore::new(directory.path()).restore(&mut Policy::new(linux(), 0.0), 0.0).is_err());
}

/// A listener that accepts and immediately closes connections.
async fn server(port: u16) -> (JoinHandle<()>, u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    (task, port)
}

async fn close(task: JoinHandle<()>) {
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn actual_tcp_success_and_refusal() {
    let (task, port) = server(0).await;
    let probe = Probe::new("127.0.0.1", port);
    assert!(tcp_probe(&probe, 0.1).await.ok);
    close(task).await;
    assert!(!tcp_probe(&probe, 0.1).await.ok);
}

#[tokio::test]
async fn quorum() {
    let (_live, port) = server(0).await;
    let (dead, dead_port) = server(0).await;
    close(dead).await;
    let mut candidate = Candidate::new("x", vec![Probe::new("127.0.0.1", port), Probe::new("127.0.0.1", dead_port)]);
    assert!(candidate_probe(&candidate, 0.1).await.ok);
    candidate.quorum = 2;
    assert!(!candidate_probe(&candidate, 0.1).await.ok);
}

async fn until(timeout: f64, mut check: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs_f64(timeout), async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("condition not reached in time");
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_real_probe_failover_and_failback() {
    let (primary, primary_port) = server(0).await;
    let (_backup, backup_port) = server(0).await;
    let mut config = configuration(BackendKind::Linux, |h| {
        (h.interval, h.timeout, h.failures, h.successes, h.failback_delay, h.stale_after) = (0.04, 0.02, 2, 2, 0.16, 0.5);
    });
    for (c, port) in config.routes[0].candidates.iter_mut().zip([primary_port, backup_port]) {
        c.probes = vec![Probe::new("127.0.0.1", port)];
    }
    (config.reconcile_interval, config.port) = (0.02, 0);
    let route = config.routes[0].clone();
    let backend = Arc::new(DryRun::default());
    let daemon = Arc::new(Daemon::new(config, backend.clone()));
    let task = tokio::spawn(daemon.clone().run());
    let selected = async |cid: &str| backend.current(&route).await.unwrap().paths == [cid];

    until(3.0, async || selected("primary").await).await;
    close(primary).await;
    until(3.0, async || selected("backup").await).await;
    let (_primary, _) = server(primary_port).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(backend.current(&route).await.unwrap().paths, ["backup"]);
    until(3.0, async || selected("primary").await).await;
    use route_discovery::http::StatusSource;
    assert_eq!(daemon.snapshot()["ready"], true);
    let history: Vec<Vec<String>> =
        backend.changes.lock().unwrap().iter().filter(|(_, d)| d.action == Action::Route).map(|(_, d)| d.paths.clone()).collect();
    assert_eq!(history, [vec!["primary"], vec!["backup"], vec!["primary"]]);
    daemon.stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), task).await.unwrap().unwrap().unwrap();
}

async fn http_get(address: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn http_status_ready_and_metrics() {
    let mut config = linux();
    config.port = 0;
    let daemon = Arc::new(Daemon::new(config, Arc::new(DryRun::default())));
    let task = tokio::spawn(daemon.clone().run());
    until(3.0, async || daemon.local_addr.lock().unwrap().is_some()).await;
    let address = daemon.local_addr.lock().unwrap().unwrap();
    for (path, code, fragment) in [
        ("/readyz", "503", r#""ready":false"#),
        ("/healthz", "200", r#""live":true"#),
        ("/metrics", "200", "route_discovery_ready 0"),
        ("/missing", "404", "not found"),
    ] {
        let response = http_get(address, path).await;
        assert!(response.starts_with(&format!("HTTP/1.1 {code}")), "{path}: {response}");
        assert!(response.contains(fragment), "{path}: {response}");
    }
    daemon.stop.cancel();
    task.await.unwrap().unwrap();
}

struct Failing;

#[async_trait]
impl Backend for Failing {
    async fn current(&self, route: &route_discovery::config::Route) -> Result<route_discovery::backends::Observed> {
        DryRun::default().current(route).await
    }

    async fn apply(&self, _route: &route_discovery::config::Route, _decision: &Decision) -> Result<bool> {
        backend_err("cannot write")
    }
}

#[tokio::test]
async fn backend_failure_does_not_commit_desired_state() {
    let config = configuration(BackendKind::Linux, |h| h.successes = 1);
    let daemon = Daemon::new(config.clone(), Arc::new(Failing));
    {
        let mut policy = daemon.policy.lock().unwrap();
        for state in policy.health.values_mut() {
            state.observe(true, monotonic(), &config.health, None, None);
        }
    }
    assert!(daemon.reconcile_once(&config.routes[0]).await.is_err());
    assert!(daemon.policy.lock().unwrap().installed[&config.routes[0].key()].is_empty());
}

struct AlwaysUp;

#[async_trait]
impl Prober for AlwaysUp {
    async fn probe(&self, _candidate: &Candidate, _timeout: f64) -> ProbeResult {
        ProbeResult { ok: true, latency_ms: Some(1.0), error: None }
    }
}

struct Valid;

#[async_trait]
impl PathValidator for Valid {
    async fn validate(&self, _config: &Config) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn frr_shutdown_withdraws_runtime_routes() {
    let mut config = configuration(BackendKind::Frr, |h| (h.successes, h.interval, h.timeout) = (1, 0.04, 0.02));
    (config.reconcile_interval, config.port) = (0.02, 0);
    let route = config.routes[0].clone();
    let backend = Arc::new(DryRun::default());
    let daemon = Arc::new(
        Daemon::new(config, backend.clone()).with_apply(true).with_prober(Arc::new(AlwaysUp)).with_validator(Arc::new(Valid)),
    );
    let task = tokio::spawn(daemon.clone().run());
    until(3.0, async || !backend.current(&route).await.unwrap().paths.is_empty()).await;
    daemon.stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), task).await.unwrap().unwrap().unwrap();
    assert_eq!(backend.current(&route).await.unwrap().action, Action::Withdraw);
}

struct BadPaths;

#[async_trait]
impl PathValidator for BadPaths {
    async fn validate(&self, _config: &Config) -> Result<()> {
        backend_err("wrong probe table")
    }
}

struct MustNotProbe(AtomicBool);

#[async_trait]
impl Prober for MustNotProbe {
    async fn probe(&self, _candidate: &Candidate, _timeout: f64) -> ProbeResult {
        self.0.store(true, Ordering::SeqCst);
        ProbeResult { ok: true, ..Default::default() }
    }
}

#[tokio::test]
async fn bad_probe_pinning_never_marks_path_healthy() {
    let config = configuration(BackendKind::Linux, |h| h.successes = 1);
    let route = config.routes[0].clone();
    let prober = Arc::new(MustNotProbe(AtomicBool::new(false)));
    let daemon = Arc::new(
        Daemon::new(config, Arc::new(DryRun::default()))
            .with_apply(true)
            .with_prober(prober.clone())
            .with_validator(Arc::new(BadPaths)),
    );
    let task = tokio::spawn(daemon.clone().probe_loop(route.clone(), 0));
    until(1.0, async || !daemon.probe_path_errors.lock().unwrap().is_empty()).await;
    daemon.stop.cancel();
    task.await.unwrap();
    assert!(!prober.0.load(Ordering::SeqCst), "probe ran with invalid path pinning");
    assert_ne!(daemon.policy.lock().unwrap().path(&route.key(), "primary").state, PathState::Up);
}
