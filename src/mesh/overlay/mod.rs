//! GRE overlay for networks without multicast: VPCs, VPC peering, Direct Connect and leased lines.
//!
//! Hosts find each other through a shared S3 registry, or a static peers file. Each site (a VPC, or a host outside AWS)
//! has relays chosen from the registry; hosts tunnel to their site's relays, and relays tunnel to
//! every other site's relays. Babel runs over the tunnels and reroutes when a path fails. Tunnel
//! packets themselves are pinned to the underlay (see `underlay`).

pub mod peers;
pub mod registry;
pub mod select;
pub mod tunnel;
pub mod underlay;

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;
use tracing::{info, warn};

use crate::clock::monotonic;
use crate::commands::{argv, Runner};
use crate::error::{Error, Result};
use registry::{Entry, Platform, Registry, Store};
use select::Selection;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformChoice {
    /// EC2 when IMDS answers, otherwise a host outside AWS.
    Auto,
    Ec2,
    Metal,
}

/// Where hosts find each other.
#[derive(Clone, Debug)]
pub enum Source {
    /// `s3://bucket/prefix`, and the bucket's region.
    Registry { url: String, region: Option<String> },
    /// A static JSON list of hosts (see `peers`).
    File(PathBuf),
}

#[derive(Clone, Debug)]
pub struct Options {
    pub source: Source,
    pub platform: PlatformChoice,
    /// Overrides the site: the VPC ID on EC2, the host ID elsewhere.
    pub site: Option<String>,
    /// Overrides the underlay address peers tunnel to.
    pub endpoint: Option<Ipv4Addr>,
    pub relays: usize,
    /// Seconds between registry syncs or peers-file reads.
    pub interval: f64,
    pub mtu: u32,
}

impl Options {
    /// A host missing this many syncs is treated as gone.
    pub fn ttl(&self) -> i64 {
        (self.interval * 5.0).ceil() as i64
    }
}

/// What the mesh needs from the overlay to shape this pass's babeld filters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shape {
    pub platform: Option<Platform>,
    pub relay: bool,
    /// The VPC's own CIDRs: the VPC fabric carries them, so they are never learned through the mesh.
    pub local: Vec<IpNet>,
    /// CIDRs this relay originates for its VPC.
    pub originate: Vec<IpNet>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Status {
    /// This host as the peers file lists it; with the registry, always the discovered identity.
    own: Option<Entry>,
    selection: Selection,
    tunnels: Vec<tunnel::Tunnel>,
    skipped: Vec<String>,
    pins: underlay::Desired,
    pending: Vec<String>,
    synced: bool,
    errors: Vec<String>,
}

pub struct Overlay {
    pub options: Options,
    /// This host as discovered from IMDS or the host itself.
    pub own: Entry,
    pub vpc_cidrs: Vec<IpNet>,
    /// The registry; `None` with a peers file.
    store: Option<Arc<dyn Store>>,
    registry: tokio::sync::Mutex<(Registry, Option<f64>)>,
    status: Mutex<Status>,
}

/// Table 4242's routes. The kernel only creates a table with its first route, and until then
/// `ip route show table` fails, so a missing table reads as empty.
async fn pinned_routes(runner: &dyn Runner) -> Result<Vec<underlay::Route>> {
    let table = underlay::TABLE.to_string();
    match runner.run(&argv(["ip", "-json", "route", "show", "table", &table]), 3.0).await {
        Ok(text) => underlay::parse_routes(&json_of(&text, "ip route")?),
        Err(e) if e.to_string().contains("FIB table does not exist") => Ok(vec![]),
        Err(e) => Err(e),
    }
}

fn json_of(text: &str, what: &str) -> Result<Value> {
    serde_json::from_str(text).map_err(|_| Error::Backend(format!("{what}: non-JSON output")))
}

impl Overlay {
    /// `own.since` is replaced by the registry's record of this host, when there is one.
    pub async fn new(options: Options, mut own: Entry, vpc_cidrs: Vec<IpNet>, store: Option<Arc<dyn Store>>) -> Result<Self> {
        // S3 being down must not stop the mesh from starting; seniority is then restored on a later restart.
        if let Some(store) = &store {
            match registry::previous_since(store.as_ref(), &own.host).await {
                Ok(Some(since)) => own.since = since,
                Ok(None) => {}
                Err(e) => warn!("registry_unavailable_at_start error={e}"),
            }
        }
        Ok(Overlay {
            options,
            own,
            vpc_cidrs,
            store,
            registry: tokio::sync::Mutex::new((Registry::default(), None)),
            status: Mutex::new(Status::default()),
        })
    }

    /// Publishes this host (or reads the peers file) and recomputes relays and peers, at most once per
    /// interval. A failed sync keeps the previous selection, so tunnels stay up while S3 is unreachable
    /// or the peers file is broken.
    async fn sync(&self, apply: bool) -> Option<String> {
        let mut guard = self.registry.lock().await;
        let now = monotonic();
        if guard.1.is_some_and(|at| now - at < self.options.interval) {
            return None;
        }
        guard.1 = Some(now);
        let found = match (&self.store, &self.options.source) {
            (Some(store), _) => guard.0.sync(store.as_ref(), &self.own, apply, unix_now()).await.map(|e| (self.own.clone(), e)),
            (None, Source::File(path)) => std::fs::read_to_string(path)
                .map_err(|e| Error::Config(format!("peers file {}: {e}", path.display())))
                .and_then(|text| peers::parse(&text))
                .and_then(|entries| peers::resolve(&self.own, entries)),
            (None, Source::Registry { .. }) => Err(Error::Config("registry not connected".into())),
        };
        match found {
            Ok((own, entries)) => {
                let selection = select::select(&own, &entries, self.options.ttl(), self.options.relays);
                let mut status = self.status.lock().unwrap();
                if status.own.as_ref().is_none_or(|o| o.host != own.host || o.site != own.site) && self.store.is_none() {
                    info!("overlay_identity host={} site={} source=peers-file", own.host, own.site);
                }
                if status.selection.relay != selection.relay {
                    info!("overlay_role relay={} site={}", selection.relay, own.site);
                }
                status.own = Some(own);
                status.selection = selection;
                status.synced = true;
                None
            }
            Err(e) if self.store.is_some() => Some(format!("registry: {e}")),
            Err(e) => Some(e.to_string()),
        }
    }

    /// This host as the mesh knows it: from the peers file once read, otherwise as discovered.
    fn current(&self, status: &Status) -> Entry {
        status.own.clone().unwrap_or_else(|| self.own.clone())
    }

    /// Brings tunnels, endpoint pins and originated routes in line with the current selection.
    pub async fn reconcile(&self, runner: &dyn Runner, apply: bool) -> Result<(Shape, Vec<String>)> {
        let mut errors: Vec<String> = self.sync(apply).await.into_iter().collect();
        let (own, selection) = {
            let status = self.status.lock().unwrap();
            (self.current(&status), status.selection.clone())
        };
        let (tunnels, skipped) = tunnel::desired(&own, &selection.peers);
        let links = tunnel::parse(&json_of(&runner.run(&argv(["ip", "-d", "-json", "addr", "show"]), 3.0).await?, "ip addr")?)?;
        let main = underlay::parse_routes(&json_of(
            &runner.run(&argv(["ip", "-json", "route", "show", "table", "main"]), 3.0).await?,
            "ip route",
        )?)?;
        let pinned = pinned_routes(runner).await?;
        let rule = underlay::has_rule(&json_of(&runner.run(&argv(["ip", "-json", "rule", "show"]), 3.0).await?, "ip rule")?);
        let ec2 = own.platform == Platform::Ec2;
        let originate = if ec2 && selection.relay { self.vpc_cidrs.clone() } else { vec![] };
        let endpoints: BTreeSet<Ipv4Addr> = tunnels.iter().map(|t| t.remote).collect();
        let pins = underlay::desired(&main, &endpoints, &originate);
        if ec2 && selection.relay && pins.originate.is_empty() && !originate.is_empty() {
            errors.push("no default route to the VPC router; VPC CIDRs not originated".into());
        }
        // Pins first, so a new tunnel's packets start on the underlay.
        let mut commands = underlay::plan(&pins, &pinned, &main, rule);
        commands.extend(tunnel::plan(&tunnels, &links, tunnel::link_local(&own.host), self.options.mtu));
        let rendered: Vec<String> = commands.iter().map(|c| c.join(" ")).collect();
        if apply {
            for command in &commands {
                info!("overlay_command {}", command.join(" "));
                runner.run(command, 5.0).await?;
            }
        } else if !commands.is_empty() {
            info!("dry_run_overlay commands={rendered:?}");
        }
        let shape = Shape {
            platform: Some(own.platform),
            relay: selection.relay,
            local: if ec2 { self.vpc_cidrs.clone() } else { vec![] },
            originate: pins.originate.keys().map(|n| IpNet::V4(*n)).collect(),
        };
        if !selection.stale.is_empty() {
            warn!("overlay_stale hosts={:?}", selection.stale);
        }
        let mut status = self.status.lock().unwrap();
        status.tunnels = tunnels;
        status.skipped = skipped;
        status.pins = pins;
        status.pending = if apply { vec![] } else { rendered };
        status.errors = errors.clone();
        Ok((shape, errors))
    }

    pub fn snapshot(&self) -> Value {
        let status = self.status.lock().unwrap();
        serde_json::json!({
            "host": self.current(&status),
            "relay": status.selection.relay,
            "synced": status.synced,
            "relays": status.selection.relays,
            "peers": status.selection.peers.iter().map(|p| serde_json::json!({"host": p.host, "name": p.name, "site": p.site, "endpoint": p.endpoint})).collect::<Vec<_>>(),
            "tunnels": status.tunnels,
            "skipped": status.skipped,
            "stale": status.selection.stale,
            "pins": status.pins,
            "pending": status.pending,
            "errors": status.errors,
        })
    }

    pub fn pending(&self) -> Vec<String> {
        self.status.lock().unwrap().pending.clone()
    }

    pub fn tunnel_count(&self) -> usize {
        self.status.lock().unwrap().tunnels.len()
    }
}

/// Removes every owned tunnel, the endpoint pins and rule, and originated routes. Needs no registry.
pub async fn withdraw(runner: &dyn Runner) -> Result<Vec<Vec<String>>> {
    let links = tunnel::parse(&json_of(&runner.run(&argv(["ip", "-d", "-json", "addr", "show"]), 3.0).await?, "ip addr")?)?;
    let main = underlay::parse_routes(&json_of(
        &runner.run(&argv(["ip", "-json", "route", "show", "table", "main"]), 3.0).await?,
        "ip route",
    )?)?;
    let pinned = pinned_routes(runner).await?;
    let rule = underlay::has_rule(&json_of(&runner.run(&argv(["ip", "-json", "rule", "show"]), 3.0).await?, "ip rule")?);
    let mut commands: Vec<Vec<String>> = links.keys().map(|name| argv(["ip", "link", "del", name])).collect();
    commands.extend(underlay::withdraw(&pinned, &main, rule));
    for command in &commands {
        runner.run(command, 5.0).await?;
    }
    Ok(commands)
}

/// Identity of a host outside AWS. `route` is `ip -json route get` output for an off-host address.
pub fn metal_identity(machine_id: &str, hostname: &str, route: &Value, options: &Options) -> Result<Entry> {
    let id: String = machine_id.trim().chars().take(16).collect();
    if id.is_empty() {
        return crate::error::config_err("empty /etc/machine-id; cannot derive a host ID");
    }
    let host = format!("metal-{id}");
    let endpoint = match options.endpoint {
        Some(endpoint) => endpoint,
        None => route
            .as_array()
            .and_then(|r| r.first())
            .and_then(|r| r["prefsrc"].as_str())
            .and_then(|a| a.parse().ok())
            .ok_or_else(|| Error::Config("no source address on the default path; pass --endpoint".into()))?,
    };
    Ok(Entry {
        site: options.site.clone().unwrap_or_else(|| host.clone()),
        host,
        name: hostname.trim().to_string(),
        platform: Platform::Metal,
        endpoint,
        since: 0,
    })
}

/// Identity of an EC2 instance; its site is its VPC.
pub fn ec2_identity(host: &crate::bgp::metadata::Host, hostname: &str, options: &Options) -> Result<(Entry, Vec<IpNet>)> {
    let endpoint = match options.endpoint {
        Some(endpoint) => endpoint,
        None => match host.router_id() {
            Some(IpAddr::V4(a)) => a,
            _ => return crate::error::backend_err("IMDS: no IPv4 address for the tunnel endpoint"),
        },
    };
    let entry = Entry {
        host: host.instance_id.clone(),
        name: hostname.trim().to_string(),
        site: options.site.clone().unwrap_or_else(|| host.vpc_id.clone()),
        platform: Platform::Ec2,
        endpoint,
        since: 0,
    };
    Ok((entry, host.vpc_cidrs.clone()))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Discovers this host and connects to the registry, or checks the peers file.
pub async fn system(options: Options, runner: &dyn Runner) -> Result<Overlay> {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let (mut own, cidrs) = match ec2_host(options.platform).await? {
        Some(found) => ec2_identity(&found, &hostname, &options)?,
        None => {
            let machine_id = std::fs::read_to_string("/etc/machine-id")?;
            let route = json_of(&runner.run(&argv(["ip", "-json", "route", "get", "192.0.2.1"]), 3.0).await?, "ip route get")?;
            (metal_identity(&machine_id, &hostname, &route, &options)?, vec![])
        }
    };
    own.since = unix_now();
    info!("overlay_identity host={} site={} platform={:?} endpoint={}", own.host, own.site, own.platform, own.endpoint);
    let store: Option<Arc<dyn Store>> = match &options.source {
        Source::Registry { url, region } => Some(registry_store(url, region.clone()).await?),
        Source::File(path) => {
            // Fail at startup on a missing or malformed file; later edits are re-read every interval.
            let text = std::fs::read_to_string(path).map_err(|e| Error::Config(format!("peers file {}: {e}", path.display())))?;
            peers::parse(&text)?;
            None
        }
    };
    Overlay::new(options, own, cidrs, store).await
}

#[cfg(feature = "aws")]
async fn ec2_host(platform: PlatformChoice) -> Result<Option<crate::bgp::metadata::Host>> {
    use crate::bgp::metadata::{host, Imds};
    Ok(match platform {
        PlatformChoice::Metal => None,
        PlatformChoice::Ec2 => Some(host(&Imds::new()).await?),
        PlatformChoice::Auto => match tokio::time::timeout(std::time::Duration::from_secs(5), host(&Imds::new())).await {
            Ok(Ok(found)) => Some(found),
            _ => None,
        },
    })
}

#[cfg(not(feature = "aws"))]
async fn ec2_host(platform: PlatformChoice) -> Result<Option<crate::bgp::metadata::Host>> {
    match platform {
        PlatformChoice::Ec2 => crate::error::config_err("--platform ec2 needs a build with the aws feature"),
        _ => Ok(None),
    }
}

#[cfg(feature = "aws")]
async fn registry_store(url: &str, region: Option<String>) -> Result<Arc<dyn Store>> {
    Ok(Arc::new(registry::S3Store::new(url, region).await?))
}

#[cfg(not(feature = "aws"))]
async fn registry_store(_url: &str, _region: Option<String>) -> Result<Arc<dyn Store>> {
    crate::error::config_err("--registry needs a build with the aws feature; use --peers-file")
}
