//! Bounded TCP probes with an explicit path selector; no shell or DNS lookup.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use socket2::{Domain, Socket, Type};
use tokio::net::TcpSocket;

use crate::config::{Candidate, Probe};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProbeResult {
    pub ok: bool,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
}

#[async_trait]
pub trait Prober: Send + Sync {
    async fn probe(&self, candidate: &Candidate, timeout: f64) -> ProbeResult;
}

/// Real TCP connect probes.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpProber;

#[async_trait]
impl Prober for TcpProber {
    async fn probe(&self, candidate: &Candidate, timeout: f64) -> ProbeResult {
        candidate_probe(candidate, timeout).await
    }
}

fn pinned_socket(probe: &Probe) -> std::io::Result<TcpSocket> {
    let socket = Socket::new(Domain::for_address(SocketAddr::new(probe.host, 0)), Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    if let Some(device) = &probe.device {
        socket.bind_device(Some(device.as_bytes()))?;
    }
    if let Some(mark) = probe.mark {
        socket.set_mark(mark)?;
    }
    if let Some(source) = probe.source {
        socket.bind(&SocketAddr::new(source, 0).into())?;
    }
    Ok(TcpSocket::from_std_stream(socket.into()))
}

pub async fn tcp_probe(probe: &Probe, timeout: f64) -> ProbeResult {
    let started = Instant::now();
    let attempt = async {
        let socket = pinned_socket(probe)?;
        socket.connect(SocketAddr::new(probe.host, probe.port)).await
    };
    match tokio::time::timeout(Duration::from_secs_f64(timeout), attempt).await {
        Ok(Ok(_stream)) => ProbeResult { ok: true, latency_ms: Some(started.elapsed().as_secs_f64() * 1000.0), error: None },
        Ok(Err(e)) => ProbeResult { ok: false, latency_ms: None, error: Some(e.to_string()) },
        Err(_) => ProbeResult { ok: false, latency_ms: None, error: Some("connect timed out".into()) },
    }
}

pub async fn candidate_probe(candidate: &Candidate, timeout: f64) -> ProbeResult {
    let results = futures::future::join_all(candidate.probes.iter().map(|p| tcp_probe(p, timeout))).await;
    let good: Vec<&ProbeResult> = results.iter().filter(|r| r.ok).collect();
    let latency = good.iter().filter_map(|r| r.latency_ms).fold(None, |max: Option<f64>, v| Some(max.map_or(v, |m| m.max(v))));
    let errors: Vec<&str> = results.iter().filter_map(|r| r.error.as_deref()).collect();
    ProbeResult {
        ok: good.len() >= candidate.quorum,
        latency_ms: latency,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}
