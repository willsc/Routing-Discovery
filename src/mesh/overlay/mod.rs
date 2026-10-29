//! GRE overlay for networks without multicast: VPCs, VPC peering, Direct Connect and leased lines.
//!
//! Hosts find each other through a shared S3 registry. Each site (a VPC, or a host outside AWS)
//! has relays chosen from the registry; hosts tunnel to their site's relays, and relays tunnel to
//! every other site's relays. Babel runs over the tunnels and reroutes when a path fails. Tunnel
//! packets themselves are pinned to the underlay (see `underlay`).

pub mod registry;
pub mod select;
pub mod tunnel;
pub mod underlay;

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
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

#[derive(Clone, Debug)]
pub struct Options {
    /// `s3://bucket/prefix`
    pub registry: String,
    pub registry_region: Option<String>,
    pub platform: PlatformChoice,
    /// Overrides the site: the VPC ID on EC2, the host ID elsewhere.
    pub site: Option<String>,
    /// Overrides the underlay address peers tunnel to.
    pub endpoint: Option<Ipv4Addr>,
    pub relays: usize,
    /// Seconds between registry syncs.
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
    pub own: Entry,
    pub vpc_cidrs: Vec<IpNet>,
    store: Arc<dyn Store>,
    registry: tokio::sync::Mutex<(Registry, Option<f64>)>,
    status: Mutex<Status>,
}

fn json_of(text: &str, what: &str) -> Result<Value> {
    serde_json::from_str(text).map_err(|_| Error::Backend(format!("{what}: non-JSON output")))
}

impl Overlay {
    /// `own.since` is replaced by the registry's record of this host, when there is one.
    pub async fn new(options: Options, mut own: Entry, vpc_cidrs: Vec<IpNet>, store: Arc<dyn Store>) -> Result<Self> {
        // S3 being down must not stop the mesh from starting; seniority is then restored on a later restart.
        match registry::previous_since(store.as_ref(), &own.host).await {
            Ok(Some(since)) => own.since = since,
            Ok(None) => {}
            Err(e) => warn!("registry_unavailable_at_start error={e}"),
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

    /// Publishes this host and recomputes relays and peers, at most once per registry interval.
    /// A failed sync keeps the previous selection, so tunnels stay up while S3 is unreachable.
    async fn sync(&self, apply: bool) -> Option<String> {
        let mut guard = self.registry.lock().await;
        let now = monotonic();
        if guard.1.is_some_and(|at| now - at < self.options.interval) {
            return None;
        }
        guard.1 = Some(now);
        match guard.0.sync(self.store.as_ref(), &self.own, apply, unix_now()).await {
            Ok(entries) => {
                let selection = select::select(&self.own, &entries, self.options.ttl(), self.options.relays);
                let mut status = self.status.lock().unwrap();
                if status.selection.relay != selection.relay {
                    info!("overlay_role relay={} site={}", selection.relay, self.own.site);
                }
                status.selection = selection;
                status.synced = true;
                None
            }
            Err(e) => Some(format!("registry: {e}")),
        }
    }

    /// Brings tunnels, endpoint pins and originated routes in line with the current selection.
    pub async fn reconcile(&self, runner: &dyn Runner, apply: bool) -> Result<(Shape, Vec<String>)> {
        let mut errors: Vec<String> = self.sync(apply).await.into_iter().collect();
        let selection = self.status.lock().unwrap().selection.clone();
        let (tunnels, skipped) = tunnel::desired(&self.own, &selection.peers);
        let links = tunnel::parse(&json_of(&runner.run(&argv(["ip", "-d", "-json", "addr", "show"]), 3.0).await?, "ip addr")?)?;
        let main = underlay::parse_routes(&json_of(
            &runner.run(&argv(["ip", "-json", "route", "show", "table", "main"]), 3.0).await?,
            "ip route",
        )?)?;
        let table = underlay::TABLE.to_string();
        let pinned = underlay::parse_routes(&json_of(
            &runner.run(&argv(["ip", "-json", "route", "show", "table", &table]), 3.0).await?,
            "ip route",
        )?)?;
        let rule = underlay::has_rule(&json_of(&runner.run(&argv(["ip", "-json", "rule", "show"]), 3.0).await?, "ip rule")?);
        let ec2 = self.own.platform == Platform::Ec2;
        let originate = if ec2 && selection.relay { self.vpc_cidrs.clone() } else { vec![] };
        let endpoints: BTreeSet<Ipv4Addr> = tunnels.iter().map(|t| t.remote).collect();
        let pins = underlay::desired(&main, &endpoints, &originate);
        if ec2 && selection.relay && pins.originate.is_empty() && !originate.is_empty() {
            errors.push("no default route to the VPC router; VPC CIDRs not originated".into());
        }
        // Pins first, so a new tunnel's packets start on the underlay.
        let mut commands = underlay::plan(&pins, &pinned, &main, rule);
        commands.extend(tunnel::plan(&tunnels, &links, tunnel::link_local(&self.own.host), self.options.mtu));
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
            platform: Some(self.own.platform),
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
            "host": self.own,
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
    let table = underlay::TABLE.to_string();
    let pinned = underlay::parse_routes(&json_of(
        &runner.run(&argv(["ip", "-json", "route", "show", "table", &table]), 3.0).await?,
        "ip route",
    )?)?;
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

/// Discovers this host and connects to the registry.
#[cfg(feature = "aws")]
pub async fn system(options: Options, runner: &dyn Runner) -> Result<Overlay> {
    use crate::bgp::metadata::{host, Imds};
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let ec2 = match options.platform {
        PlatformChoice::Metal => None,
        PlatformChoice::Ec2 => Some(host(&Imds::new()).await?),
        PlatformChoice::Auto => match tokio::time::timeout(std::time::Duration::from_secs(5), host(&Imds::new())).await {
            Ok(Ok(found)) => Some(found),
            _ => None,
        },
    };
    let (mut own, cidrs) = match ec2 {
        Some(found) => ec2_identity(&found, &hostname, &options)?,
        None => {
            let machine_id = std::fs::read_to_string("/etc/machine-id")?;
            let route = json_of(&runner.run(&argv(["ip", "-json", "route", "get", "192.0.2.1"]), 3.0).await?, "ip route get")?;
            (metal_identity(&machine_id, &hostname, &route, &options)?, vec![])
        }
    };
    own.since = unix_now();
    info!("overlay_identity host={} site={} platform={:?} endpoint={}", own.host, own.site, own.platform, own.endpoint);
    let store = Arc::new(registry::S3Store::new(&options.registry, options.registry_region.clone()).await?);
    Overlay::new(options, own, cidrs, store).await
}

#[cfg(not(feature = "aws"))]
pub async fn system(_options: Options, _runner: &dyn Runner) -> Result<Overlay> {
    crate::error::config_err("--registry needs a build with the aws feature")
}
