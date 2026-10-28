//! Zero-configuration BGP to AWS. Each pass discovers this instance from IMDS, finds the VPC
//! Route Server and Transit Gateway Connect peers that name its ENI addresses, provisions Connect
//! GRE tunnels, and applies a bgpd configuration announcing the service prefixes on its interfaces.
//!
//! AWS carries the routes onward: Route Server into VPC route tables, the TGW to other VPCs,
//! VPN attachments and Direct Connect gateways. bgpd keeps its sessions if this process stops.

pub mod advertise;
pub mod discovery;
pub mod frr;
pub mod gre;
pub mod metadata;
pub mod registration;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::clock::monotonic;
use crate::commands::{argv, Runner};
use crate::error::{backend_err, Error, Result};
use crate::http::{self, StatusSource};
use crate::mesh::inventory::Filter;
use crate::state::StateStore;
use crate::supervision::notify;
use advertise::Announcements;
use discovery::{Discovered, Peering};
use frr::Session;
use metadata::{Host, Metadata};

/// A reload is repeated at least this often, so manual bgpd edits are reverted.
const DRIFT_RELOAD: f64 = 300.0;
/// Seconds a peer must stay orphaned before the sweep deletes it.
pub const SWEEP_GRACE: f64 = 300.0;

#[derive(Clone, Debug)]
pub struct Options {
    pub filter: Filter,
    pub policy: frr::Policy,
    pub frr_reload: String,
    pub vty_socket: Option<String>,
    pub interval: f64,
    pub listen: IpAddr,
    pub port: u16,
    pub state_dir: PathBuf,
    pub apply: bool,
    /// Create this instance's Route Server peers; None leaves peering resources to IaC.
    pub register: Option<registration::Registration>,
    /// Delete tagged Route Server peers whose owner instance has terminated.
    pub sweep: bool,
}

/// Everything one pass decided, before any change is made.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Observation {
    pub host: Option<Host>,
    pub discovered: Discovered,
    pub announcements: Announcements,
    /// Neighbors denied announcements, with the reason.
    pub gated: BTreeMap<IpAddr, String>,
    pub tunnel_commands: Vec<Vec<String>>,
    pub registration: registration::Changes,
    pub orphans: Vec<registration::Orphan>,
    pub config: String,
}

#[derive(Default)]
struct Status {
    observation: Observation,
    sessions: BTreeMap<String, Session>,
    converged: bool,
    passes: u64,
    errors: Vec<String>,
}

pub struct Controller {
    pub options: Options,
    pub stop: CancellationToken,
    metadata: Arc<dyn Metadata>,
    aws: Arc<dyn Peering>,
    runner: Arc<dyn Runner>,
    status: Mutex<Status>,
    /// Last configuration bgpd accepted, and when.
    applied: Mutex<Option<(String, f64)>>,
    /// When each orphaned peer was first observed.
    orphaned_since: Mutex<BTreeMap<String, f64>>,
}

async fn pause(stop: &CancellationToken, seconds: f64) {
    tokio::select! {
        _ = stop.cancelled() => {}
        _ = tokio::time::sleep(Duration::from_secs_f64(seconds)) => {}
    }
}

fn json_of(text: &str, what: &str) -> Result<Value> {
    serde_json::from_str(text).map_err(|_| Error::Backend(format!("{what}: non-JSON output")))
}

impl Controller {
    pub fn new(options: Options, metadata: Arc<dyn Metadata>, aws: Arc<dyn Peering>, runner: Arc<dyn Runner>) -> Self {
        Controller {
            options,
            stop: CancellationToken::new(),
            metadata,
            aws,
            runner,
            status: Mutex::new(Status::default()),
            applied: Mutex::new(None),
            orphaned_since: Mutex::new(BTreeMap::new()),
        }
    }

    fn vtysh(&self, command: &str) -> Vec<String> {
        let mut args = argv(["vtysh"]);
        if let Some(dir) = &self.options.vty_socket {
            args.extend(argv(["--vty_socket", dir]));
        }
        args.extend(argv(["-c", command]));
        args
    }

    pub async fn observe(&self) -> Result<Observation> {
        let host = metadata::host(self.metadata.as_ref()).await?;
        let (peers, connects) = futures::try_join!(self.aws.route_server_peers(), self.aws.connect_peers())?;
        let endpoints = if self.options.register.is_some() { self.aws.route_server_endpoints().await? } else { vec![] };
        let ids: BTreeSet<String> =
            peers.iter().map(|p| p.route_server_id.clone()).chain(endpoints.iter().map(|e| e.route_server_id.clone())).collect();
        let asns = self.aws.route_server_asns(&ids.into_iter().collect::<Vec<_>>()).await?;
        let discovered = discovery::resolve(&host, &peers, &asns, &connects);
        let registration = match &self.options.register {
            Some(r) => registration::plan(&host, &endpoints, &peers, &asns, r),
            None => registration::Changes::default(),
        };
        let orphans = if self.options.sweep {
            let states = self.aws.instance_states(&registration::owners(&host, &peers)).await?;
            registration::orphans(&host, &peers, &states)
        } else {
            vec![]
        };
        let interfaces = json_of(&self.runner.run(&argv(["ip", "-d", "-json", "addr", "show"]), 3.0).await?, "ip addr")?;
        let announcements = advertise::select(&interfaces, &self.options.filter, &host)?;
        let enis: BTreeSet<String> = discovered.neighbors.iter().filter_map(|n| n.eni.clone()).collect();
        let checks = self.aws.source_dest_checks(&enis.into_iter().collect::<Vec<_>>()).await?;
        // With the check on, EC2 drops traffic addressed to an announced prefix: announcing would black-hole it.
        let gated: BTreeMap<IpAddr, String> = discovered
            .neighbors
            .iter()
            .filter_map(|n| {
                let eni = n.eni.as_ref()?;
                checks
                    .get(eni)
                    .copied()
                    .unwrap_or(true)
                    .then(|| (n.address, format!("source/destination check enabled on {eni}")))
            })
            .collect();
        let gated_set: BTreeSet<IpAddr> = gated.keys().copied().collect();
        let router_id = host.router_id().ok_or_else(|| Error::Backend("no IPv4 address for a BGP router ID".into()))?;
        let config = frr::render(&frr::Plan {
            router_id,
            neighbors: &discovered.neighbors,
            announce: &announcements.prefixes,
            vpc_cidrs: &host.vpc_cidrs,
            gated: &gated_set,
            policy: &self.options.policy,
        });
        let tunnel_commands = gre::plan(&discovered.tunnels, &gre::parse(&interfaces)?);
        Ok(Observation { host: Some(host), discovered, announcements, gated, tunnel_commands, registration, orphans, config })
    }

    fn config_path(&self) -> PathBuf {
        self.options.state_dir.join("bgpd.conf")
    }

    async fn write_config(&self, text: &str) -> Result<PathBuf> {
        let path = self.config_path();
        let temporary = path.with_extension("conf.tmp");
        tokio::fs::write(&temporary, text).await?;
        tokio::fs::rename(&temporary, &path).await?;
        Ok(path)
    }

    fn reload_args(&self, path: &std::path::Path, mode: &str) -> Vec<String> {
        let mut args = argv([self.options.frr_reload.as_str(), mode, "--daemon", "bgpd"]);
        if let Some(dir) = &self.options.vty_socket {
            args.extend(argv(["--vty_socket", dir]));
        }
        args.push(path.display().to_string());
        args
    }

    /// `frr-reload.py --test` output: what a reload would change.
    pub async fn diff(&self, config: &str) -> Result<String> {
        let path = self.write_config(config).await?;
        self.runner.run(&self.reload_args(&path, "--test"), 30.0).await
    }

    /// Apply Route Server registration, tunnels, then bgpd. Returns true when nothing is left to do.
    /// A peer created in this pass is `pending`; the next pass discovers it once AWS makes it available.
    pub async fn reconcile(&self, observation: &Observation) -> Result<bool> {
        let changes = &observation.registration;
        if !self.options.apply {
            if !observation.tunnel_commands.is_empty() {
                info!("dry_run_tunnels commands={:?}", observation.tunnel_commands);
            }
            if !changes.is_empty() {
                info!("dry_run_registration create={:?} delete={:?}", changes.create, changes.delete);
            }
            return Ok(observation.tunnel_commands.is_empty() && changes.is_empty());
        }
        for id in &changes.delete {
            info!("route_server_peer_delete id={id}");
            self.aws.delete_route_server_peer(id).await?;
        }
        for request in &changes.create {
            let id = self.aws.create_route_server_peer(request).await?;
            info!("route_server_peer_create id={id} endpoint={} address={}", request.endpoint_id, request.peer_address);
        }
        for command in &observation.tunnel_commands {
            info!("gre_command {}", command.join(" "));
            self.runner.run(command, 5.0).await?;
        }
        let now = monotonic();
        let current = self.applied.lock().unwrap().clone();
        let fresh = current.as_ref().is_some_and(|(text, at)| *text == observation.config && now - at < DRIFT_RELOAD);
        if !fresh {
            let path = self.write_config(&observation.config).await?;
            info!("bgpd_reload path={}", path.display());
            self.runner.run(&self.reload_args(&path, "--reload"), 60.0).await?;
            *self.applied.lock().unwrap() = Some((observation.config.clone(), now));
        }
        Ok(changes.is_empty())
    }

    /// Delete peers orphaned for at least SWEEP_GRACE. Failures are reported, not fatal: another
    /// instance may be deleting the same peer, and the next pass retries.
    pub async fn sweep(&self, observation: &Observation, now: f64) -> Vec<String> {
        let due = registration::due(&mut self.orphaned_since.lock().unwrap(), &observation.orphans, now, SWEEP_GRACE);
        let mut errors = vec![];
        for id in due {
            let orphan = observation.orphans.iter().find(|o| o.peer == id).unwrap();
            if !self.options.apply {
                info!("dry_run_sweep peer={id} owner={} reason={}", orphan.owner, orphan.reason);
                continue;
            }
            match self.aws.delete_route_server_peer(&id).await {
                Ok(()) => {
                    info!("route_server_peer_sweep peer={id} owner={} reason={}", orphan.owner, orphan.reason);
                    self.orphaned_since.lock().unwrap().remove(&id);
                }
                Err(e) => errors.push(format!("sweep {id}: {e}")),
            }
        }
        errors
    }

    async fn sessions(&self) -> Result<BTreeMap<String, Session>> {
        let text = self.runner.run(&self.vtysh("show bgp summary json"), 5.0).await?;
        frr::parse_summary(&json_of(&text, "bgp summary")?)
    }

    async fn pass(&self) -> (bool, Vec<String>) {
        let mut errors = vec![];
        let converged = match self.observe().await {
            Ok(observation) => {
                for (address, reason) in &observation.gated {
                    errors.push(format!("{address}: announcements withheld: {reason}"));
                }
                let result = self.reconcile(&observation).await;
                errors.extend(self.sweep(&observation, monotonic()).await);
                self.status.lock().unwrap().observation = observation;
                result.unwrap_or_else(|e| {
                    errors.push(e.to_string());
                    false
                })
            }
            Err(e) => {
                errors.push(e.to_string());
                false
            }
        };
        match self.sessions().await {
            Ok(sessions) => self.status.lock().unwrap().sessions = sessions,
            Err(e) => errors.push(format!("sessions: {e}")),
        }
        (converged, errors)
    }

    async fn control_loop(self: Arc<Self>) {
        let mut delay = self.options.interval;
        while !self.stop.is_cancelled() {
            let (converged, errors) = self.pass().await;
            for e in &errors {
                warn!("bgp_pass {e}");
            }
            {
                let mut status = self.status.lock().unwrap();
                status.converged = converged;
                status.errors = errors;
                status.passes += 1;
            }
            notify("WATCHDOG=1");
            delay = if converged { self.options.interval } else { (delay * 2.0).min(60.0) };
            pause(&self.stop, delay * (0.9 + fastrand::f64() * 0.2)).await;
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind((self.options.listen, self.options.port)).await?;
        notify("READY=1");
        let source: Arc<dyn StatusSource> = self.clone();
        let server = tokio::spawn(http::serve(listener, source, self.stop.clone()));
        self.clone().control_loop().await;
        let _ = server.await;
        notify("STOPPING=1");
        info!("bgp controller stopped; bgpd keeps its sessions and announcements");
        Ok(())
    }
}

/// Established sessions for every discovered neighbor, and none gated.
fn ready(status: &Status) -> bool {
    let neighbors = &status.observation.discovered.neighbors;
    status.converged
        && status.errors.is_empty()
        && !neighbors.is_empty()
        && neighbors.iter().all(|n| status.sessions.get(&n.address.to_string()).is_some_and(|s| s.state == "Established"))
}

impl StatusSource for Controller {
    fn snapshot(&self) -> Value {
        let status = self.status.lock().unwrap();
        let o = &status.observation;
        json!({
            "live": true,
            "ready": ready(&status),
            "apply": self.options.apply,
            "converged": status.converged,
            "passes": status.passes,
            "host": o.host,
            "neighbors": o.discovered.neighbors,
            "tunnels": o.discovered.tunnels,
            "ignored": o.discovered.ignored.iter().chain(&o.registration.ignored).collect::<Vec<_>>(),
            "registration": {"create": o.registration.create, "delete": o.registration.delete},
            "orphans": o.orphans,
            "announced": o.announcements.prefixes,
            "withheld": o.announcements.withheld,
            "sessions": status.sessions,
            "errors": status.errors,
        })
    }

    fn metrics(&self) -> String {
        let status = self.status.lock().unwrap();
        let o = &status.observation;
        let established = status.sessions.values().filter(|s| s.state == "Established").count();
        let mut lines = vec![
            format!("bgp_ready {}", u8::from(ready(&status))),
            format!("bgp_neighbors {}", o.discovered.neighbors.len()),
            format!("bgp_sessions_established {established}"),
            format!("bgp_announced_prefixes {}", o.announcements.prefixes.len()),
            format!("bgp_gated_neighbors {}", o.gated.len()),
            format!("bgp_orphaned_peers {}", o.orphans.len()),
        ];
        for (address, s) in &status.sessions {
            lines.push(format!("bgp_session_up{{neighbor=\"{address}\"}} {}", u8::from(s.state == "Established")));
            if let Some(n) = s.received {
                lines.push(format!("bgp_prefixes_received{{neighbor=\"{address}\"}} {n}"));
            }
        }
        lines.join("\n") + "\n"
    }
}

#[cfg(feature = "aws")]
pub async fn system(options: Options) -> Result<Controller> {
    let imds: Arc<dyn Metadata> = Arc::new(metadata::Imds::new());
    let host = metadata::host(imds.as_ref()).await?;
    let aws: Arc<dyn Peering> = Arc::new(discovery::SdkPeering::new(&host.region).await);
    Ok(Controller::new(options, imds, aws, Arc::new(crate::commands::SystemRunner)))
}

#[cfg(not(feature = "aws"))]
pub async fn system(_options: Options) -> Result<Controller> {
    backend_err("this build lacks the `aws` feature; rebuild with --features aws")
}

pub async fn run(options: Options) -> Result<()> {
    let directory = if options.apply { options.state_dir.clone() } else { options.state_dir.join("dry-run") };
    let mut lock = StateStore::new(&directory);
    lock.acquire()?;
    let options = Options { state_dir: directory, ..options };
    let controller = Arc::new(system(options).await?);
    crate::server::stop_on_signals(controller.stop.clone())?;
    let result = controller.run().await;
    lock.close();
    result
}

/// Remove owned GRE tunnels and Route Server peers, and replace bgpd's configuration with the bare filters.
pub async fn withdraw(controller: &Controller) -> Result<()> {
    let interfaces = json_of(&controller.runner.run(&argv(["ip", "-d", "-json", "addr", "show"]), 3.0).await?, "ip addr")?;
    let empty = frr::render(&frr::Plan {
        router_id: IpAddr::from([0, 0, 0, 0]),
        neighbors: &[],
        announce: &BTreeSet::new(),
        vpc_cidrs: &[],
        gated: &BTreeSet::new(),
        policy: &controller.options.policy,
    });
    let path = controller.write_config(&empty).await?;
    controller.runner.run(&controller.reload_args(&path, "--reload"), 60.0).await?;
    for command in gre::plan(&[], &gre::parse(&interfaces)?) {
        controller.runner.run(&command, 5.0).await?;
    }
    // Sessions are already down, so deleting the peers cannot strand traffic on a stale route.
    let host = metadata::host(controller.metadata.as_ref()).await?;
    for id in registration::owned(&host, &controller.aws.route_server_peers().await?) {
        info!("route_server_peer_delete id={id}");
        controller.aws.delete_route_server_peer(&id).await?;
    }
    if controller.sessions().await?.is_empty() {
        Ok(())
    } else {
        backend_err("bgpd still reports sessions after withdrawal")
    }
}
