use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use toml::{Table, Value};

use crate::config::read_toml;
use crate::error::{config_err, Result};
use crate::toml_check::*;

pub fn networks(values: Option<&Value>, required: bool) -> Result<Vec<String>> {
    let message = "prefix allowlists must be arrays of 1–256 canonical networks";
    let values = match values {
        None if !required => return Ok(Vec::new()),
        v => array(v, message)?,
    };
    if (required && values.is_empty()) || values.len() > 256 {
        return config_err(message);
    }
    let result: Vec<String> = values
        .iter()
        .map(|v| v.as_str().and_then(parse_network).map(|n| n.to_string()))
        .collect::<Option<_>>()
        .map_or_else(|| config_err(format!("{message}; host bits must be zero")), Ok)?;
    if result.iter().collect::<HashSet<_>>().len() != result.len() {
        return config_err("duplicate prefix in allowlist");
    }
    Ok(result)
}

/// True when `prefix` is equal to or more specific than an allowlisted network of its family.
pub fn permits(prefix: &str, allowed: &[String]) -> bool {
    let Ok(net) = prefix.parse::<IpNet>() else { return false };
    allowed.iter().filter_map(|p| p.parse::<IpNet>().ok()).any(|parent| parent.contains(&net))
}

pub fn version(prefix: &str) -> u8 {
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V6(_)) => 6,
        _ => 4,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Endpoint {
    pub id: String,
    pub address: IpAddr,
    pub router_id: Ipv4Addr,
    pub socket_dir: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Peer {
    pub id: String,
    pub endpoint: String,
    pub address: IpAddr,
    pub asn: u32,
    pub eni: String,
    pub next_hops: Vec<String>,
    pub allowed_prefixes: Vec<String>,
    pub max_prefixes: usize,
    pub local_pref: u32,
    pub bfd: bool,
}

impl Peer {
    pub fn versions(&self) -> std::collections::BTreeSet<u8> {
        self.allowed_prefixes.iter().map(|p| version(p)).collect()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Propagation {
    pub table: String,
    pub allowed_prefixes: Vec<String>,
    pub enabled: bool,
    pub max_routes: usize,
}

impl Propagation {
    pub fn new(table: &str) -> Self {
        Propagation { table: table.into(), allowed_prefixes: Vec::new(), enabled: true, max_routes: 100 }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerConfig {
    pub id: String,
    pub asn: u32,
    pub region: String,
    pub vpc_id: String,
    pub endpoints: Vec<Endpoint>,
    pub peers: Vec<Peer>,
    pub propagations: Vec<Propagation>,
    pub state_dir: PathBuf,
    pub listen: IpAddr,
    pub port: u16,
    pub poll_interval: f64,
    pub reconcile_interval: f64,
    pub stale_after: f64,
    pub failback_delay: f64,
    pub persist_routes: bool,
    pub persist_duration: f64,
    pub owner_tag: String,
}

impl ServerConfig {
    pub fn peers_of<'a>(&'a self, endpoint: &'a str) -> impl Iterator<Item = &'a Peer> + 'a {
        self.peers.iter().filter(move |p| p.endpoint == endpoint)
    }
}

const SERVER_KEYS: &[&str] = &[
    "id",
    "asn",
    "region",
    "vpc_id",
    "state_dir",
    "listen",
    "port",
    "poll_interval",
    "reconcile_interval",
    "stale_after",
    "failback_delay",
    "persist_routes",
    "persist_duration",
    "owner_tag",
];
const U32_MAX: i64 = u32::MAX as i64;

pub fn load(path: impl AsRef<Path>) -> Result<ServerConfig> {
    parse(&read_toml(path.as_ref())?)
}

fn list<'a>(raw: &'a Table, key: &str, upper: usize) -> Result<&'a Vec<Value>> {
    match raw.get(key).and_then(Value::as_array) {
        Some(values) if (1..=upper).contains(&values.len()) => Ok(values),
        _ => config_err(format!("configure 1–{upper} {key}")),
    }
}

fn parse_endpoint(raw: &Value) -> Result<Endpoint> {
    let e = table(raw, "endpoint")?;
    check_keys(e, &["id", "address", "router_id", "socket_dir"], "endpoint")?;
    let id = name(e.get("id"), "endpoint.id")?;
    let address = address(e.get("address"), "endpoint.address")?;
    let router_id = match e.get("router_id").and_then(Value::as_str).and_then(|s| s.parse::<Ipv4Addr>().ok()) {
        Some(r) => r,
        None => return config_err("endpoint.router_id must be an IPv4 address"),
    };
    let socket_dir = match e.get("socket_dir").and_then(Value::as_str) {
        Some(s) if Path::new(s).is_absolute() && !s.contains('\n') => s.to_string(),
        _ => return config_err("endpoint.socket_dir must be an absolute FRR socket directory"),
    };
    Ok(Endpoint { id, address, router_id, socket_dir })
}

fn parse_peer(raw: &Value, endpoints: &[Endpoint], asn: u32) -> Result<Peer> {
    let p = table(raw, "peer")?;
    check_keys(
        p,
        &["id", "endpoint", "address", "asn", "eni", "next_hops", "allowed_prefixes", "max_prefixes", "local_pref", "bfd"],
        "peer",
    )?;
    let id = name(p.get("id"), "peer.id")?;
    let Some(endpoint) = p.get("endpoint").and_then(Value::as_str).and_then(|e| endpoints.iter().find(|x| x.id == e)) else {
        return config_err(format!("{id}: unknown endpoint"));
    };
    let peer_address = address(p.get("address"), "peer.address")?;
    if !same_family(peer_address, endpoint.address) || peer_address == endpoint.address {
        return config_err("peer and endpoint need different addresses in the same address family");
    }
    let peer_asn = required_int(p.get("asn"), "peer.asn", 1, U32_MAX)? as u32;
    if peer_asn == asn {
        return config_err("route-server peers must use eBGP with a different ASN");
    }
    let hops = match p.get("next_hops").and_then(Value::as_array) {
        Some(h) if (1..=8).contains(&h.len()) => h,
        _ => return config_err("each peer needs 1–8 next_hops mapped to its ENI"),
    };
    let next_hops: Vec<String> =
        hops.iter().map(|h| address(Some(h), "next_hop").map(|ip| ip.to_string())).collect::<Result<_>>()?;
    if next_hops.iter().collect::<HashSet<_>>().len() != next_hops.len() {
        return config_err("duplicate next hop");
    }
    let bfd = boolean(p.get("bfd"), true, "bfd must be boolean")?;
    Ok(Peer {
        id,
        endpoint: endpoint.id.clone(),
        address: peer_address,
        asn: peer_asn,
        eni: resource(p.get("eni"), "eni")?,
        next_hops,
        allowed_prefixes: networks(p.get("allowed_prefixes"), true)?,
        max_prefixes: int(p.get("max_prefixes"), 100, "max_prefixes", 1, 10000)? as usize,
        local_pref: int(p.get("local_pref"), 100, "local_pref", 0, U32_MAX)? as u32,
        bfd,
    })
}

fn parse_propagation(raw: &Value) -> Result<Propagation> {
    let t = table(raw, "propagation")?;
    check_keys(t, &["table", "allowed_prefixes", "enabled", "max_routes"], "propagation")?;
    let enabled = boolean(t.get("enabled"), true, "propagation.enabled must be boolean")?;
    Ok(Propagation {
        table: resource(t.get("table"), "rtb")?,
        allowed_prefixes: networks(t.get("allowed_prefixes"), false)?,
        enabled,
        max_routes: int(t.get("max_routes"), 100, "max_routes", 1, 10000)? as usize,
    })
}

pub fn parse(raw: &Table) -> Result<ServerConfig> {
    check_keys(raw, &["server", "endpoints", "peers", "propagations"], "route-server config")?;
    let empty = Table::new();
    let s = sub_table(raw, "server", &empty)?;
    check_keys(s, SERVER_KEYS, "server")?;
    let id = name(s.get("id"), "server.id")?;
    let asn = required_int(s.get("asn"), "server.asn", 1, U32_MAX)? as u32;
    let region = match s.get("region").and_then(Value::as_str) {
        Some(r) if is_region(r) => r.to_string(),
        _ => return config_err("server.region is required"),
    };
    let vpc_id = resource(s.get("vpc_id"), "vpc")?;
    let (endpoint_list, peer_list, propagation_list) =
        (list(raw, "endpoints", 16)?, list(raw, "peers", 128)?, list(raw, "propagations", 64)?);
    let endpoints = endpoint_list.iter().map(parse_endpoint).collect::<Result<Vec<_>>>()?;
    let unique = |values: Vec<String>| values.iter().collect::<HashSet<_>>().len() == values.len();
    for (attribute, values) in [
        ("id", endpoints.iter().map(|e| e.id.clone()).collect()),
        ("address", endpoints.iter().map(|e| e.address.to_string()).collect()),
        ("router_id", endpoints.iter().map(|e| e.router_id.to_string()).collect()),
        ("socket_dir", endpoints.iter().map(|e| e.socket_dir.clone()).collect::<Vec<_>>()),
    ] {
        if !unique(values) {
            return config_err(format!("endpoints require unique {attribute} values"));
        }
    }
    let peers = peer_list.iter().map(|p| parse_peer(p, &endpoints, asn)).collect::<Result<Vec<_>>>()?;
    if !unique(peers.iter().map(|p| p.id.clone()).collect())
        || !unique(peers.iter().map(|p| format!("{}|{}", p.endpoint, p.address)).collect())
    {
        return config_err("duplicate peer ID or endpoint/peer address");
    }
    if let Some(e) = endpoints.iter().find(|e| !peers.iter().any(|p| p.endpoint == e.id)) {
        return config_err(format!("endpoint {} has no peers", e.id));
    }
    let propagations = propagation_list.iter().map(parse_propagation).collect::<Result<Vec<_>>>()?;
    if !unique(propagations.iter().map(|t| t.table.clone()).collect()) {
        return config_err("duplicate propagation table");
    }
    let poll_interval = float(s.get("poll_interval"), 1.0, "poll_interval", 0.1, 3600.0)?;
    let reconcile_interval = float(s.get("reconcile_interval"), 5.0, "reconcile_interval", 0.1, 3600.0)?;
    let stale_after = float(s.get("stale_after"), 10.0, "stale_after", 0.1, 3600.0)?;
    if stale_after < 2.0 * poll_interval {
        return config_err("stale_after must be at least twice poll_interval");
    }
    let owner_tag = match s.get("owner_tag") {
        None => "route-discovery-server".to_string(),
        Some(Value::String(t)) if is_owner_tag(t) => t.clone(),
        Some(_) => return config_err("invalid owner_tag"),
    };
    let state_dir = match s.get("state_dir") {
        None => PathBuf::from("/var/lib/route-discovery-server"),
        Some(Value::String(d)) if Path::new(d).is_absolute() => PathBuf::from(d),
        Some(_) => return config_err("state_dir must be an absolute path"),
    };
    Ok(ServerConfig {
        id,
        asn,
        region,
        vpc_id,
        endpoints,
        peers,
        propagations,
        state_dir,
        listen: match s.get("listen") {
            None => IpAddr::from([127, 0, 0, 1]),
            v => address(v, "listen")?,
        },
        port: int(s.get("port"), 9809, "port", 0, 65535)? as u16,
        poll_interval,
        reconcile_interval,
        stale_after,
        failback_delay: float(s.get("failback_delay"), 10.0, "failback_delay", 0.0, 3600.0)?,
        persist_routes: boolean(s.get("persist_routes"), false, "persist_routes must be boolean")?,
        persist_duration: float(s.get("persist_duration"), 60.0, "persist_duration", 60.0, 300.0)?,
        owner_tag,
    })
}
