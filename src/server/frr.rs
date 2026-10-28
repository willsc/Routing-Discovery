//! FRR JSON adapter. Unknown/malformed output is a source failure, never an empty RIB.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::config::{permits, version, Endpoint, Peer, ServerConfig};
use super::rib::{LearnedRoute, PeerState, Rejected, Snapshot};
use crate::commands::{argv, Runner, SystemRunner};
use crate::error::{backend_err, Error, Result};
use crate::toml_check::parse_network;

type Parse<T> = std::result::Result<T, String>;

fn uint(value: Option<&Value>, field: &str) -> Parse<u32> {
    value.and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok()).ok_or_else(|| format!("invalid {field}"))
}

/// `\d+( +\d+)*` in asplain notation; AS_SETs and confederations are rejected.
fn as_path(raw: Option<&Value>) -> Parse<Vec<u32>> {
    let text = raw.and_then(Value::as_str).unwrap_or_default();
    let shape = !text.is_empty()
        && text.chars().all(|c| c.is_ascii_digit() || c == ' ')
        && !text.starts_with(' ')
        && !text.ends_with(' ');
    if !shape {
        return Err("only nonempty AS_SEQUENCE paths in asplain notation are supported".into());
    }
    text.split_whitespace().map(|a| a.parse::<u32>().map_err(|_| "invalid AS number".to_string())).collect()
}

fn learn(
    config: &ServerConfig,
    endpoint: &Endpoint,
    peer: &Peer,
    state: &PeerState,
    ver: u8,
    prefix: &str,
    path: &Value,
) -> Parse<LearnedRoute> {
    if !state.up || !state.bgp.get(&ver).copied().unwrap_or(false) {
        return Err("peer unavailable".into());
    }
    let truthy = |key: &str| path.get(key).is_some_and(|v| !matches!(v, Value::Null | Value::Bool(false)));
    if path.get("valid") != Some(&Value::Bool(true)) || ["stale", "removed", "suppressed", "damped"].iter().any(|k| truthy(k)) {
        return Err("route invalid, stale or suppressed".into());
    }
    if !permits(prefix, &peer.allowed_prefixes) {
        return Err("prefix outside peer allowlist".into());
    }
    let as_path = as_path(path.get("path"))?;
    if as_path.len() > 255 || as_path.contains(&0) || as_path[0] != peer.asn || as_path.contains(&config.asn) {
        return Err("AS path loop, first-AS mismatch or invalid AS path".into());
    }
    let next_hops = path.get("nexthops").and_then(Value::as_array).ok_or("missing next hops")?;
    let mut hops = BTreeSet::new();
    for hop in next_hops {
        if let Some(ip) = hop.get("ip") {
            let parsed: IpAddr = ip.as_str().and_then(|s| s.parse().ok()).ok_or("invalid next hop address")?;
            hops.insert(parsed.to_string());
        }
    }
    let allowed: Vec<&String> = hops.iter().filter(|h| peer.next_hops.contains(h)).collect();
    let Some(next_hop) = allowed.first() else { return Err("next hop outside the peer's configured ENI addresses".into()) };
    let med = match path.get("metric") {
        None => 0,
        some => uint(some, "MED")?,
    };
    Ok(LearnedRoute {
        prefix: prefix.to_string(),
        peer: peer.id.clone(),
        endpoint: endpoint.id.clone(),
        eni: peer.eni.clone(),
        next_hop: (*next_hop).clone(),
        as_path,
        med,
        local_pref: peer.local_pref,
    })
}

fn parse_inner(config: &ServerConfig, endpoint: &Endpoint, data: &Value) -> Parse<Snapshot> {
    let summary = data.get("summary").filter(|s| s.is_object()).ok_or("missing BGP summary")?;
    let peers: Vec<&Peer> = config.peers_of(&endpoint.id).collect();
    let peer_map: HashMap<String, &Peer> = peers.iter().map(|p| (p.address.to_string(), *p)).collect();
    let bfd = match data.get("bfd") {
        None => &Vec::new(),
        Some(Value::Array(rows)) if rows.iter().all(Value::is_object) => rows,
        Some(_) => return Err("invalid BFD peer list".into()),
    };
    let families: BTreeSet<u8> = peers.iter().flat_map(|p| p.versions()).collect();
    let mut tables = BTreeMap::new();
    for &v in &families {
        let af = summary.get(format!("ipv{v}Unicast"));
        if !af.and_then(|s| s.get("peers")).is_some_and(Value::is_object) {
            return Err(format!("missing IPv{v} peer summary"));
        }
        let routes = data.get(format!("ipv{v}")).and_then(|r| r.get("routes")).and_then(Value::as_object);
        tables.insert(v, routes.ok_or_else(|| format!("missing IPv{v} routes object"))?);
    }
    let mut states: BTreeMap<String, PeerState> = BTreeMap::new();
    for peer in &peers {
        let address = peer.address.to_string();
        let mut af_state = BTreeMap::new();
        for v in peer.versions() {
            let record = &summary[format!("ipv{v}Unicast")]["peers"][&address];
            // Missing configured peers are a configuration fault, not a healthy empty RIB.
            if !record.is_object() || record.get("state").is_none() || record.get("remoteAs").is_none() {
                return Err(format!("missing configured peer {} in IPv{v} summary", peer.id));
            }
            af_state.insert(v, record["state"] == "Established" && record["remoteAs"].as_u64() == Some(peer.asn.into()));
        }
        let local = endpoint.address.to_string();
        let rows: Vec<&Value> = bfd
            .iter()
            .filter(|r| {
                r.get("peer").and_then(Value::as_str) == Some(address.as_str())
                    && r.get("local").and_then(Value::as_str).unwrap_or(&local) == local
                    && r.get("vrf").and_then(Value::as_str).unwrap_or("default") == "default"
            })
            .collect();
        let bfd_up = !peer.bfd || (rows.len() == 1 && rows[0].get("status").and_then(Value::as_str) == Some("up"));
        let up = af_state.values().any(|&s| s) && bfd_up;
        let bfd_label = match (peer.bfd, bfd_up) {
            (false, _) => "disabled",
            (true, true) => "up",
            (true, false) => "down",
        };
        states.insert(
            peer.id.clone(),
            PeerState {
                up,
                bgp: af_state,
                bfd: Some(bfd_label.into()),
                reason: Some(if up { "available" } else { "BGP/BFD unavailable" }.into()),
            },
        );
    }
    let mut routes = Vec::new();
    let mut rejected = Vec::new();
    let mut counts: HashMap<&str, BTreeSet<String>> = peers.iter().map(|p| (p.id.as_str(), BTreeSet::new())).collect();
    for (&v, table) in &tables {
        for (prefix, paths) in table.iter() {
            let net = parse_network(prefix).ok_or("invalid routes table schema")?;
            let paths = paths.as_array().filter(|_| version(&net.to_string()) == v).ok_or("invalid routes table schema")?;
            for path in paths {
                if !path.is_object() {
                    return Err("invalid route entry".into());
                }
                // Local or unconfigured peer routes cannot enter this controller.
                let Some(peer) = path.get("peerId").and_then(Value::as_str).and_then(|id| peer_map.get(id)) else { continue };
                counts.get_mut(peer.id.as_str()).map(|c| c.insert(prefix.clone()));
                match learn(config, endpoint, peer, &states[&peer.id], v, prefix, path) {
                    Ok(route) => routes.push(route),
                    Err(reason) => rejected.push(Rejected { prefix: Some(prefix.clone()), peer: peer.id.clone(), reason }),
                }
            }
        }
    }
    let over: BTreeSet<String> =
        peers.iter().filter(|p| counts[p.id.as_str()].len() > p.max_prefixes).map(|p| p.id.clone()).collect();
    for pid in &over {
        if let Some(state) = states.get_mut(pid) {
            state.up = false;
            state.reason = Some("maximum prefix limit exceeded".into());
        }
        rejected.push(Rejected {
            prefix: None,
            peer: pid.clone(),
            reason: "maximum prefix limit exceeded; all peer routes rejected".into(),
        });
    }
    routes.retain(|r| !over.contains(&r.peer));
    // Add-path routes with the same mapped next hop have one deterministic local representative.
    routes.sort_by(|a, b| (a.rank(), &a.as_path).cmp(&(b.rank(), &b.as_path)));
    let mut seen = std::collections::HashSet::new();
    routes.retain(|r| seen.insert(r.key()));
    Ok(Snapshot { routes, peers: states, rejected })
}

pub fn parse_snapshot(config: &ServerConfig, endpoint: &Endpoint, data: &Value) -> Result<Snapshot> {
    parse_inner(config, endpoint, data).map_err(|e| Error::Backend(format!("{}: invalid FRR snapshot: {e}", endpoint.id)))
}

#[async_trait]
pub trait Source: Send + Sync {
    async fn read(&self, endpoint: &Endpoint) -> Result<Snapshot>;
}

pub struct FrrSource {
    config: ServerConfig,
    run: Arc<dyn Runner>,
}

impl FrrSource {
    pub fn new(config: ServerConfig, runner: Arc<dyn Runner>) -> Self {
        FrrSource { config, run: runner }
    }

    pub fn system(config: ServerConfig) -> Self {
        Self::new(config, Arc::new(SystemRunner))
    }

    async fn query(&self, endpoint: &Endpoint, command: &str) -> Result<Value> {
        let output = self.run.run(&argv(["vtysh", "--vty_socket", &endpoint.socket_dir, "-c", command]), 3.0).await?;
        serde_json::from_str(&output).map_err(|_| Error::Backend(format!("{}: non-JSON response for {command}", endpoint.id)))
    }
}

#[async_trait]
impl Source for FrrSource {
    async fn read(&self, endpoint: &Endpoint) -> Result<Snapshot> {
        let peers: Vec<&Peer> = self.config.peers_of(&endpoint.id).collect();
        let versions: BTreeSet<u8> = peers.iter().flat_map(|p| p.versions()).collect();
        let before = self.query(endpoint, "show bgp summary json").await?;
        let commands: Vec<String> = versions.iter().map(|v| format!("show bgp ipv{v} unicast json")).collect();
        let values = futures::future::try_join_all(commands.iter().map(|c| self.query(endpoint, c))).await?;
        let bfd =
            if peers.iter().any(|p| p.bfd) { self.query(endpoint, "show bfd peers json").await? } else { Value::Array(vec![]) };
        let after = self.query(endpoint, "show bgp summary json").await?;
        // Detect a session change during the sample. This is polling, not an atomic FRR snapshot.
        for v in &versions {
            let key = format!("ipv{v}Unicast");
            for peer in &peers {
                let address = peer.address.to_string();
                let a = &before[&key]["peers"][&address];
                let b = &after[&key]["peers"][&address];
                if ["state", "remoteAs", "peerUptimeEstablishedEpoch"].iter().any(|f| a.get(f) != b.get(f)) {
                    return backend_err(format!("{}/{}: BGP session changed during snapshot", endpoint.id, peer.id));
                }
            }
        }
        let mut data = serde_json::json!({"summary": after, "bfd": bfd});
        for (v, value) in versions.iter().zip(values) {
            data[format!("ipv{v}")] = value;
        }
        parse_snapshot(&self.config, endpoint, &data)
    }
}

pub fn render(config: &ServerConfig, endpoint_id: &str) -> Result<String> {
    let Some(endpoint) = config.endpoints.iter().find(|e| e.id == endpoint_id) else {
        return Err(Error::Config("unknown endpoint".into()));
    };
    let peers: Vec<&Peer> = config.peers_of(endpoint_id).collect();
    let mut lines = vec![
        format!("! Dedicated FRR instance for route-discovery route-server endpoint {}", endpoint.id),
        "! Run zebra/bgpd/bfdd with this endpoint's socket directory and listen address.".into(),
        "route-map RDS-DENY-OUT deny 10".into(),
        "!".into(),
    ];
    for (index, peer) in peers.iter().enumerate().map(|(i, p)| (i + 1, p)) {
        for v in [4u8, 6] {
            let cmd = if v == 4 { "ip" } else { "ipv6" };
            let maximum = if v == 4 { 32 } else { 128 };
            let prefixes: Vec<&String> = peer.allowed_prefixes.iter().filter(|p| version(p) == v).collect();
            for (n, prefix) in prefixes.iter().enumerate() {
                let length = parse_network(prefix).map_or(0, |net| net.prefix_len());
                let le = if length == maximum { String::new() } else { format!(" le {maximum}") };
                lines.push(format!("{cmd} prefix-list RDS-P{index}-V{v} seq {} permit {prefix}{le}", (n + 1) * 10));
            }
            if !prefixes.is_empty() {
                lines.extend([
                    format!("route-map RDS-P{index}-V{v} permit 10"),
                    format!(" match {cmd} address prefix-list RDS-P{index}-V{v}"),
                    format!(" set local-preference {}", peer.local_pref),
                    "!".into(),
                ]);
            }
        }
    }
    lines.extend([
        format!("router bgp {}", config.asn),
        format!(" bgp router-id {}", endpoint.router_id),
        " no bgp default ipv4-unicast".into(),
        " bgp bestpath as-path multipath-relax".into(),
        " bgp always-compare-med".into(),
    ]);
    for peer in &peers {
        lines.extend([
            format!(" neighbor {} remote-as {}", peer.address, peer.asn),
            format!(" neighbor {} update-source {}", peer.address, endpoint.address),
            format!(" neighbor {} timers 3 9", peer.address),
        ]);
        if peer.bfd {
            lines.push(format!(" neighbor {} bfd", peer.address));
        }
    }
    for v in [4u8, 6] {
        let active: Vec<(usize, &&Peer)> =
            peers.iter().enumerate().map(|(i, p)| (i + 1, p)).filter(|(_, p)| p.versions().contains(&v)).collect();
        if active.is_empty() {
            continue;
        }
        lines.push(format!(" address-family ipv{v} unicast"));
        for (index, peer) in active {
            lines.extend([
                format!("  neighbor {} activate", peer.address),
                format!("  neighbor {} route-map RDS-P{index}-V{v} in", peer.address),
                format!("  neighbor {} route-map RDS-DENY-OUT out", peer.address),
                format!("  neighbor {} maximum-prefix {}", peer.address, peer.max_prefixes),
            ]);
        }
        lines.push(" exit-address-family".into());
    }
    // Last: FRR 8.x warns if -n/-l already selected no-rib, which can reset file parsing context.
    lines.push(" bgp no-rib".into());
    Ok(lines.join("\n") + "\n")
}
