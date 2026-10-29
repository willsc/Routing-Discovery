//! Zero-configuration mesh: publish this host's NICs and connected subnets through FRR babeld.
//!
//! The daemon only derives and reconciles babeld configuration; FRR does neighbour discovery,
//! link costing, loop-free path selection and FIB installation. Babel keeps routing with the last
//! applied configuration if this process stops, so it is deliberately left in place on exit.

pub mod frr;
pub mod inventory;
pub mod overlay;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::commands::{Runner, SystemRunner};
use crate::error::Result;
use crate::http::{self, StatusSource};
use crate::state::StateStore;
use crate::supervision::notify;
use frr::{Desired, MeshRoute, Policy, Vtysh};
use inventory::{Filter, Inventory};
use overlay::registry::Platform;
use overlay::Overlay;

#[derive(Clone, Debug)]
pub struct Options {
    pub filter: Filter,
    pub policy: Policy,
    pub socket_dir: Option<String>,
    pub interval: f64,
    pub listen: IpAddr,
    pub port: u16,
    pub state_dir: PathBuf,
    pub apply: bool,
    /// GRE overlay through the shared registry; `None` meshes only links that carry multicast.
    pub overlay: Option<overlay::Options>,
}

#[derive(Default)]
struct Status {
    inventory: Inventory,
    routes: Vec<MeshRoute>,
    neighbours: Vec<String>,
    pending: Vec<String>,
    converged: bool,
    passes: u64,
    errors: Vec<String>,
    /// Registry and routing warnings from the overlay; the overlay keeps working through them.
    overlay_errors: Vec<String>,
}

pub struct Mesh {
    pub options: Options,
    pub stop: CancellationToken,
    runner: Arc<dyn Runner>,
    status: Mutex<Status>,
    local_addr: Mutex<Option<SocketAddr>>,
    overlay: Option<Overlay>,
}

async fn pause(stop: &CancellationToken, seconds: f64) {
    tokio::select! {
        _ = stop.cancelled() => {}
        _ = tokio::time::sleep(Duration::from_secs_f64(seconds)) => {}
    }
}

impl Mesh {
    pub fn new(options: Options, runner: Arc<dyn Runner>) -> Self {
        Mesh {
            options,
            stop: CancellationToken::new(),
            runner,
            status: Mutex::new(Status::default()),
            local_addr: Mutex::new(None),
            overlay: None,
        }
    }

    pub fn with_overlay(mut self, overlay: Overlay) -> Self {
        self.overlay = Some(overlay);
        self
    }

    /// This pass's interface filter and babeld policy, shaped by the overlay when there is one.
    /// On EC2 only tunnels carry Babel: VPC NICs have no multicast and no neighbours to find.
    async fn shape(&self) -> Result<(Filter, Policy, Vec<String>)> {
        let (mut filter, mut policy) = (self.options.filter.clone(), self.options.policy.clone());
        let Some(overlay) = &self.overlay else { return Ok((filter, policy, vec![])) };
        let (shape, errors) = overlay.reconcile(self.runner.as_ref(), self.options.apply).await?;
        let tunnels = format!("{}*", overlay::tunnel::PREFIX);
        if shape.platform == Some(Platform::Ec2) {
            filter = Filter { include: vec![tunnels], exclude: vec![] };
            policy.leaf = !shape.relay;
        } else if !filter.include.is_empty() {
            filter.include.push(tunnels);
        }
        policy.local = shape.local;
        policy.originate = shape.originate;
        Ok((filter, policy, errors))
    }

    fn vtysh(&self) -> Vtysh<'_> {
        Vtysh { runner: self.runner.as_ref(), socket_dir: self.options.socket_dir.as_deref() }
    }

    /// One observe/plan/apply/verify pass. `stuck` holds a plan FRR did not absorb, so it is not replayed every pass.
    pub async fn pass(&self, stuck: &mut Option<(Desired, Vec<String>)>) -> Result<bool> {
        let (filter, policy, overlay_errors) = self.shape().await?;
        self.status.lock().unwrap().overlay_errors = overlay_errors;
        let inventory = inventory::collect(self.runner.as_ref(), &filter).await?;
        let desired = frr::desired(&inventory, &policy);
        self.status.lock().unwrap().inventory = inventory;
        let vtysh = self.vtysh();
        let running = vtysh.running().await?;
        let commands = frr::plan(&desired, &running);
        self.status.lock().unwrap().pending = commands.clone();
        if commands.is_empty() {
            *stuck = None;
            return Ok(true);
        }
        if stuck.as_ref().is_some_and(|(d, c)| d == &desired && c == &commands) {
            return Ok(false);
        }
        if !self.options.apply {
            info!("dry_run_plan commands={commands:?}");
            *stuck = Some((desired, commands));
            return Ok(false);
        }
        info!("babel_reconcile commands={commands:?}");
        vtysh.configure(&commands).await?;
        let after = vtysh.running().await?;
        if let Err(e) = frr::ensure_converged(&desired, &after) {
            warn!("{e}");
            let remaining = frr::plan(&desired, &after);
            *stuck = Some((desired, remaining));
            return Ok(false);
        }
        self.status.lock().unwrap().pending.clear();
        *stuck = None;
        Ok(true)
    }

    /// Inventory, babeld config and overlay commands one pass would produce; changes nothing when not applying.
    pub async fn preview(&self) -> Result<(Inventory, Desired, Vec<String>)> {
        let (filter, policy, _) = self.shape().await?;
        let inventory = inventory::collect(self.runner.as_ref(), &filter).await?;
        let desired = frr::desired(&inventory, &policy);
        let pending = self.overlay.as_ref().map(Overlay::pending).unwrap_or_default();
        Ok((inventory, desired, pending))
    }

    pub fn overlay_snapshot(&self) -> Option<Value> {
        self.overlay.as_ref().map(Overlay::snapshot)
    }

    async fn observe(&self) -> Vec<String> {
        let vtysh = self.vtysh();
        let mut errors = vec![];
        match vtysh.routes().await {
            Ok(routes) => self.status.lock().unwrap().routes = routes,
            Err(e) => errors.push(format!("routes: {e}")),
        }
        match vtysh.neighbours().await {
            Ok(neighbours) => self.status.lock().unwrap().neighbours = neighbours,
            Err(e) => errors.push(format!("neighbours: {e}")),
        }
        errors
    }

    async fn control_loop(self: Arc<Self>) {
        let mut stuck = None;
        let mut delay = self.options.interval;
        while !self.stop.is_cancelled() {
            let outcome = self.pass(&mut stuck).await;
            let mut errors = self.observe().await;
            let converged = match outcome {
                Ok(converged) => converged,
                Err(e) => {
                    error!("mesh_pass_error error={e}");
                    errors.insert(0, e.to_string());
                    false
                }
            };
            {
                let mut status = self.status.lock().unwrap();
                status.converged = converged;
                errors.extend(status.overlay_errors.iter().cloned());
                status.errors = errors;
                status.passes += 1;
            }
            notify("WATCHDOG=1");
            delay = if converged { self.options.interval } else { (delay * 2.0).min(30.0) };
            pause(&self.stop, delay * (0.9 + fastrand::f64() * 0.2)).await;
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind((self.options.listen, self.options.port)).await?;
        *self.local_addr.lock().unwrap() = Some(listener.local_addr()?);
        notify("READY=1");
        let source: Arc<dyn StatusSource> = self.clone();
        let server = tokio::spawn(http::serve(listener, source, self.stop.clone()));
        self.clone().control_loop().await;
        let _ = server.await;
        notify("STOPPING=1");
        info!("mesh controller stopped; babeld keeps its configuration and routes");
        Ok(())
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.lock().unwrap()
    }
}

impl StatusSource for Mesh {
    fn snapshot(&self) -> Value {
        let status = self.status.lock().unwrap();
        json!({
            "live": true,
            "ready": status.converged && status.errors.is_empty(),
            "apply": self.options.apply,
            "converged": status.converged,
            "passes": status.passes,
            "nics": status.inventory.nics,
            "skipped": status.inventory.skipped,
            "withheld": status.inventory.withheld,
            "neighbours": status.neighbours,
            "routes": status.routes,
            "pending": status.pending,
            "errors": status.errors,
            "overlay": self.overlay.as_ref().map(Overlay::snapshot),
        })
    }

    fn metrics(&self) -> String {
        let status = self.status.lock().unwrap();
        let ready = status.converged && status.errors.is_empty();
        let prefixes = status.inventory.prefixes().len();
        [
            format!("mesh_ready {}", u8::from(ready)),
            format!("mesh_nics {}", status.inventory.nics.len()),
            format!("mesh_published_prefixes {prefixes}"),
            format!("mesh_neighbours {}", status.neighbours.len()),
            format!("mesh_routes {}", status.routes.len()),
            format!("mesh_pending_commands {}", status.pending.len()),
            format!("mesh_tunnels {}", self.overlay.as_ref().map_or(0, Overlay::tunnel_count)),
        ]
        .join("\n")
            + "\n"
    }
}

pub async fn run(options: Options) -> Result<()> {
    let directory = if options.apply { options.state_dir.clone() } else { options.state_dir.join("dry-run") };
    let mut lock = StateStore::new(&directory);
    lock.acquire()?;
    let mut mesh = Mesh::new(options.clone(), Arc::new(SystemRunner));
    if let Some(overlay_options) = options.overlay {
        mesh = mesh.with_overlay(overlay::system(overlay_options, &SystemRunner).await?);
    }
    let mesh = Arc::new(mesh);
    crate::supervision::stop_on_signals(mesh.stop.clone())?;
    let result = mesh.run().await;
    lock.close();
    result
}

/// Remove this mode's babeld instance and filters, then its tunnels, endpoint pins and originated
/// routes; routes learned through Babel are withdrawn by FRR.
pub async fn withdraw(socket_dir: Option<&str>) -> Result<()> {
    let vtysh = Vtysh { runner: &SystemRunner, socket_dir };
    let commands = frr::withdraw_plan(&vtysh.running().await?);
    vtysh.configure(&commands).await?;
    let after = vtysh.running().await?;
    if after.router || !after.lists.is_empty() {
        return crate::error::backend_err("babel withdrawal did not converge");
    }
    for command in overlay::withdraw(&SystemRunner).await? {
        info!("overlay_withdraw {}", command.join(" "));
    }
    Ok(())
}
