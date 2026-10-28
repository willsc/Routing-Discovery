//! Self-hosted BGP-to-VPC route-server control plane.

pub mod config;
pub mod daemon;
pub mod demo;
pub mod frr;
pub mod journal;
pub mod propagation;
pub mod rib;

use std::sync::{Arc, Mutex};

use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

use crate::error::{backend_err, Result};
use crate::state::StateStore;
use config::ServerConfig;
use daemon::RouteServer;
use frr::FrrSource;
use journal::Journal;
use propagation::Propagator;

/// Stop on SIGINT/SIGTERM.
pub fn stop_on_signals(stop: CancellationToken) -> Result<()> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        stop.cancel();
    });
    Ok(())
}

pub async fn run(config: ServerConfig, apply: bool, withdraw: bool) -> Result<()> {
    let directory = if apply { config.state_dir.clone() } else { config.state_dir.join("dry-run") };
    let mut lock = StateStore::new(&directory);
    lock.acquire()?;
    if withdraw && !directory.join(journal::FILE).is_file() {
        return backend_err("withdraw requires the existing ownership journal; no routes will be adopted");
    }
    let journal = Arc::new(Mutex::new(Journal::open(&config, Some(&directory))?));
    let client = if apply { Some(crate::aws::client(&config.region).await?) } else { None };
    let mut propagator = Propagator::new(config.clone(), journal.clone(), client, apply)?;
    if withdraw {
        // No peer ENI verification is needed to retire previously owned routes.
        propagator.verify = false;
        let converged = propagator.reconcile(&Default::default(), &|| true).await?;
        println!("{}", serde_json::to_string_pretty(&propagator.status_json()).unwrap_or_default());
        if !converged {
            return backend_err("withdrawal incomplete; inspect errors and retry with the same state directory");
        }
        return journal.lock().unwrap().save_fib(&Default::default());
    }
    let source = Arc::new(FrrSource::system(config.clone()));
    let server = Arc::new(RouteServer::new(config, journal, source, propagator)?);
    stop_on_signals(server.stop.clone())?;
    let result = server.run().await;
    lock.close();
    result
}
