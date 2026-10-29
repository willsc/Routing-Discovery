//! On-prem Direct Connect router role. Each pass reads this router's private and transit VIFs
//! from the Direct Connect API, provisions VLAN interfaces for VIFs on mapped ports, and applies a
//! bgpd configuration that peers with AWS on every VIF and announces this router's on-prem subnets.
//!
//! bgpd keeps its sessions if this process stops; AWS carries the routes to VGWs, Direct Connect
//! gateways and Transit Gateways.

pub mod frr;
pub mod vif;
pub mod vlan;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipnet::IpNet;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::bgp::frr::{parse_summary, Session};
use crate::clock::monotonic;
use crate::commands::{argv, Runner};
use crate::error::{backend_err, Error, Result};
use crate::http::{self, StatusSource};
use crate::mesh::inventory::Filter;
use crate::state::StateStore;
use crate::supervision::{notify, stop_on_signals};
use vif::{DirectConnect, Discovered};

/// A reload is repeated at least this often, so manual bgpd edits are reverted.
const DRIFT_RELOAD: f64 = 300.0;

#[derive(Clone, Debug)]
pub struct Options {
    pub regions: Vec<String>,
    /// Connection or LAG ID to the local parent interface its VIFs arrive on.
    pub ports: BTreeMap<String, String>,
    pub filter: Filter,
    /// Extra prefixes (aggregates) to announce; each needs a matching route in the RIB.
    pub announce: Vec<IpNet>,
    pub policy: frr::Policy,
    pub frr_reload: String,
    pub vty_socket: Option<String>,
    pub interval: f64,
    pub listen: IpAddr,
    pub port: u16,
    pub state_dir: PathBuf,
    pub apply: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Withheld {
    pub prefix: IpNet,
    pub interface: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Observation {
    pub discovered: Discovered,
    pub announced: BTreeSet<IpNet>,
    pub withheld: Vec<Withheld>,
    /// Why announcements are withheld from every VIF, if they are.
    pub gated: Option<String>,
    pub link_commands: Vec<Vec<String>>,
    #[serde(skip)]
    pub config: String,
}

fn routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => !(a.is_loopback() || a.is_link_local() || a.is_unspecified() || a.is_multicast()),
        IpAddr::V6(a) => !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_unicast_link_local()),
    }
}

/// Every address configured on this router, for matching VIF customer addresses.
pub fn local_addresses(data: &Value) -> Vec<IpAddr> {
    data.as_array()
        .into_iter()
        .flatten()
        .flat_map(|l| l["addr_info"].as_array().into_iter().flatten())
        .filter_map(|a| a["local"].as_str()?.parse().ok())
        .collect()
}

/// Connected on-prem subnets to announce. VIF peering links are never announced.
pub fn announcements(data: &Value, filter: &Filter, discovered: &Discovered) -> Result<(BTreeSet<IpNet>, Vec<Withheld>)> {
    let links = data.as_array().ok_or_else(|| Error::Backend("ip -json addr: expected an array".into()))?;
    let peering: BTreeSet<IpNet> = discovered.neighbors.iter().map(|n| n.local.trunc()).collect();
    let mut announced = BTreeSet::new();
    let mut withheld = vec![];
    for link in links {
        let name = link["ifname"].as_str().unwrap_or_default();
        if name.starts_with(vlan::PREFIX) || filter.excludes(name) {
            continue;
        }
        let up = link["flags"].as_array().into_iter().flatten().any(|f| f == "UP");
        for info in link["addr_info"].as_array().into_iter().flatten() {
            let (Some(local), Some(length)) = (info["local"].as_str(), info["prefixlen"].as_u64()) else { continue };
            let Ok(address) = local.parse::<IpAddr>() else { continue };
            let Ok(net) = IpNet::new(address, length as u8).map(|n| n.trunc()) else { continue };
            if !routable(address) {
                continue;
            }
            let reason = if peering.contains(&net) {
                Some("Direct Connect peering link")
            } else if !up {
                Some("interface down")
            } else if info["tentative"].as_bool() == Some(true) || info["dadfailed"].as_bool() == Some(true) {
                Some("address not yet usable")
            } else {
                None
            };
            match reason {
                Some(reason) => withheld.push(Withheld { prefix: net, interface: name.to_string(), reason: reason.into() }),
                None => {
                    announced.insert(net);
                }
            }
        }
    }
    withheld.retain(|w| !announced.contains(&w.prefix));
    Ok((announced, withheld))
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
    dx: Arc<dyn DirectConnect>,
    runner: Arc<dyn Runner>,
    status: Mutex<Status>,
    applied: Mutex<Option<(String, f64)>>,
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
    pub fn new(options: Options, dx: Arc<dyn DirectConnect>, runner: Arc<dyn Runner>) -> Self {
        Controller {
            options,
            stop: CancellationToken::new(),
            dx,
            runner,
            status: Mutex::new(Status::default()),
            applied: Mutex::new(None),
        }
    }

    pub async fn observe(&self) -> Result<Observation> {
        let interfaces = json_of(&self.runner.run(&argv(["ip", "-d", "-json", "addr", "show"]), 3.0).await?, "ip addr")?;
        let vifs = self.dx.virtual_interfaces().await?;
        let discovered = vif::resolve(&vifs, &local_addresses(&interfaces), &self.options.ports);
        let (mut announced, withheld) = announcements(&interfaces, &self.options.filter, &discovered)?;
        announced.extend(self.options.announce.iter().map(IpNet::trunc));
        let per_family = |v4: bool| announced.iter().filter(|n| matches!(n, IpNet::V4(_)) == v4).count();
        // Over the limit AWS idles the session; announcing nothing keeps AWS routes flowing to on-prem.
        let gated = [true, false].into_iter().find(|v4| per_family(*v4) > frr::VIF_PREFIX_LIMIT).map(|v4| {
            format!(
                "{} IPv{} prefixes exceed the Direct Connect limit of {}; announcements withheld (use --exclude or aggregates)",
                per_family(v4),
                if v4 { 4 } else { 6 },
                frr::VIF_PREFIX_LIMIT
            )
        });
        let router_id = local_addresses(&interfaces)
            .into_iter()
            .find(|a| a.is_ipv4() && routable(*a))
            .or_else(|| discovered.neighbors.iter().map(|n| n.local.addr()).find(IpAddr::is_ipv4))
            .ok_or_else(|| Error::Backend("no IPv4 address for a BGP router ID".into()))?;
        let config = frr::render(&frr::Plan {
            router_id,
            neighbors: &discovered.neighbors,
            announce: &announced,
            gated: gated.is_some(),
            policy: &self.options.policy,
        });
        let link_commands = vlan::plan(&discovered.links, &vlan::parse(&interfaces)?);
        Ok(Observation { discovered, announced, withheld, gated, link_commands, config })
    }

    fn config_path(&self) -> PathBuf {
        self.options.state_dir.join("bgpd.conf")
    }

    /// The file holds VIF MD5 keys: written 0600 and renamed into place.
    fn write_config(&self, text: &str) -> Result<PathBuf> {
        use std::io::Write;
        let path = self.config_path();
        let temporary = path.with_extension("conf.tmp");
        let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, &path)?;
        Ok(path)
    }

    fn reload_args(&self, path: &Path, mode: &str) -> Vec<String> {
        let mut args = argv([self.options.frr_reload.as_str(), mode, "--daemon", "bgpd"]);
        if let Some(dir) = &self.options.vty_socket {
            args.extend(argv(["--vty_socket", dir]));
        }
        args.push(path.display().to_string());
        args
    }

    pub async fn diff(&self, config: &str) -> Result<String> {
        let path = self.write_config(config)?;
        self.runner.run(&self.reload_args(&path, "--test"), 30.0).await
    }

    /// VLAN links first, so bgpd finds the peering addresses when it reloads.
    pub async fn reconcile(&self, observation: &Observation) -> Result<bool> {
        if !self.options.apply {
            if !observation.link_commands.is_empty() {
                info!("dry_run_links commands={:?}", observation.link_commands);
            }
            return Ok(observation.link_commands.is_empty());
        }
        for command in &observation.link_commands {
            info!("vlan_command {}", command.join(" "));
            self.runner.run(command, 5.0).await?;
        }
        let now = monotonic();
        let current = self.applied.lock().unwrap().clone();
        let fresh = current.as_ref().is_some_and(|(text, at)| *text == observation.config && now - at < DRIFT_RELOAD);
        if !fresh {
            let path = self.write_config(&observation.config)?;
            info!("bgpd_reload path={}", path.display());
            self.runner.run(&self.reload_args(&path, "--reload"), 60.0).await?;
            *self.applied.lock().unwrap() = Some((observation.config.clone(), now));
        }
        Ok(true)
    }

    async fn sessions(&self) -> Result<BTreeMap<String, Session>> {
        let mut args = argv(["vtysh"]);
        if let Some(dir) = &self.options.vty_socket {
            args.extend(argv(["--vty_socket", dir]));
        }
        args.extend(argv(["-c", "show bgp summary json"]));
        parse_summary(&json_of(&self.runner.run(&args, 5.0).await?, "bgp summary")?)
    }

    async fn pass(&self) -> (bool, Vec<String>) {
        let mut errors = vec![];
        let converged = match self.observe().await {
            Ok(observation) => {
                errors.extend(observation.gated.clone());
                let result = self.reconcile(&observation).await;
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
                warn!("dx_pass {e}");
            }
            {
                let mut status = self.status.lock().unwrap();
                status.converged = converged;
                status.errors = errors;
                status.passes += 1;
            }
            notify("WATCHDOG=1");
            delay = if converged { self.options.interval } else { (delay * 2.0).min(120.0) };
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
        info!("dx controller stopped; bgpd keeps its sessions and announcements");
        Ok(())
    }
}

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
            "neighbors": o.discovered.neighbors,
            "links": o.discovered.links,
            "ignored": o.discovered.ignored,
            "announced": o.announced,
            "withheld": o.withheld,
            "gated": o.gated,
            "sessions": status.sessions,
            "errors": status.errors,
        })
    }

    fn metrics(&self) -> String {
        let status = self.status.lock().unwrap();
        let o = &status.observation;
        let established = status.sessions.values().filter(|s| s.state == "Established").count();
        let mut lines = vec![
            format!("dx_ready {}", u8::from(ready(&status))),
            format!("dx_neighbors {}", o.discovered.neighbors.len()),
            format!("dx_sessions_established {established}"),
            format!("dx_announced_prefixes {}", o.announced.len()),
            format!("dx_gated {}", u8::from(o.gated.is_some())),
        ];
        for (address, s) in &status.sessions {
            lines.push(format!("dx_session_up{{neighbor=\"{address}\"}} {}", u8::from(s.state == "Established")));
            if let Some(n) = s.received {
                lines.push(format!("dx_prefixes_received{{neighbor=\"{address}\"}} {n}"));
            }
        }
        lines.join("\n") + "\n"
    }
}

#[cfg(feature = "aws")]
pub async fn system(options: Options) -> Result<Controller> {
    let dx: Arc<dyn DirectConnect> = Arc::new(vif::SdkDirectConnect::new(&options.regions).await?);
    Ok(Controller::new(options, dx, Arc::new(crate::commands::SystemRunner)))
}

#[cfg(not(feature = "aws"))]
pub async fn system(_options: Options) -> Result<Controller> {
    backend_err("this build lacks the `aws` feature; rebuild with --features aws")
}

pub async fn run(options: Options) -> Result<()> {
    let directory = if options.apply { options.state_dir.clone() } else { options.state_dir.join("dry-run") };
    let mut lock = StateStore::new(&directory);
    lock.acquire()?;
    let controller = Arc::new(system(Options { state_dir: directory, ..options }).await?);
    stop_on_signals(controller.stop.clone())?;
    let result = controller.run().await;
    lock.close();
    result
}

/// Replace bgpd's configuration with the bare filters, then remove owned VLAN links.
pub async fn withdraw(controller: &Controller) -> Result<()> {
    let empty = frr::render(&frr::Plan {
        router_id: IpAddr::from([0, 0, 0, 0]),
        neighbors: &[],
        announce: &BTreeSet::new(),
        gated: false,
        policy: &controller.options.policy,
    });
    let path = controller.write_config(&empty)?;
    controller.runner.run(&controller.reload_args(&path, "--reload"), 60.0).await?;
    let interfaces = json_of(&controller.runner.run(&argv(["ip", "-d", "-json", "addr", "show"]), 3.0).await?, "ip addr")?;
    for command in vlan::plan(&[], &vlan::parse(&interfaces)?) {
        controller.runner.run(&command, 5.0).await?;
    }
    if controller.sessions().await?.is_empty() {
        Ok(())
    } else {
        backend_err("bgpd still reports sessions after withdrawal")
    }
}
