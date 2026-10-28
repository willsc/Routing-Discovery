//! Strict configuration: a typo in routing policy must never be ignored.

use std::cmp::Reverse;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::Serialize;
use toml::{Table, Value};

use crate::error::{config_err, Error, Result};
use crate::toml_check::*;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Probe {
    pub host: IpAddr,
    pub port: u16,
    pub source: Option<IpAddr>,
    pub device: Option<String>,
    pub mark: Option<u32>,
    /// External path isolation is required for the AWS API backend.
    pub external_path: Option<String>,
}

impl Probe {
    pub fn new(host: &str, port: u16) -> Self {
        Probe { host: host.parse().expect("literal IP"), port, source: None, device: None, mark: None, external_path: None }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub id: String,
    pub probes: Vec<Probe>,
    pub quorum: usize,
    pub gateway: Option<IpAddr>,
    pub device: Option<String>,
    pub aws_target: Option<String>,
    pub local_pref: u32,
    pub as_path: Vec<u32>,
    pub med: u32,
    pub cost: u32,
    pub enabled: bool,
}

pub type Rank = (Reverse<u32>, usize, u32, u32);

impl Candidate {
    pub fn new(id: &str, probes: Vec<Probe>) -> Self {
        Candidate {
            id: id.into(),
            probes,
            quorum: 1,
            gateway: None,
            device: None,
            aws_target: None,
            local_pref: 100,
            as_path: Vec::new(),
            med: 0,
            cost: 0,
            enabled: true,
        }
    }

    /// Deliberate local policy: MED always compared across candidates.
    pub fn rank(&self) -> Rank {
        (Reverse(self.local_pref), self.as_path.len(), self.med, self.cost)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AllDown {
    Withdraw,
    Retain,
    Unreachable,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub prefix: IpNet,
    pub candidates: Vec<Candidate>,
    pub max_paths: usize,
    pub preempt: bool,
    pub all_down: AllDown,
}

impl Route {
    pub fn new(prefix: &str, candidates: Vec<Candidate>) -> Self {
        Route { prefix: prefix.parse().expect("prefix"), candidates, max_paths: 1, preempt: true, all_down: AllDown::Withdraw }
    }

    pub fn key(&self) -> String {
        self.prefix.to_string()
    }

    pub fn is_v6(&self) -> bool {
        matches!(self.prefix, IpNet::V6(_))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Health {
    pub interval: f64,
    pub timeout: f64,
    pub failures: u32,
    pub successes: u32,
    pub failback_delay: f64,
    pub stale_after: f64,
    pub dampening_half_life: f64,
    pub dampening_penalty: f64,
    pub dampening_suppress: f64,
    pub dampening_reuse: f64,
    pub dampening_max: f64,
}

impl Default for Health {
    fn default() -> Self {
        Health {
            interval: 1.0,
            timeout: 0.3,
            failures: 3,
            successes: 3,
            failback_delay: 10.0,
            stale_after: 5.0,
            dampening_half_life: 30.0,
            dampening_penalty: 1000.0,
            dampening_suppress: 2500.0,
            dampening_reuse: 750.0,
            dampening_max: 120.0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    Linux,
    Aws,
    Frr,
}

impl BackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BackendKind::Linux => "linux",
            BackendKind::Aws => "aws",
            BackendKind::Frr => "frr",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Backend {
    pub kind: BackendKind,
    pub table: u32,
    pub protocol: u8,
    pub metric: u32,
    pub region: Option<String>,
    pub route_table_id: Option<String>,
    pub owner_tag: String,
    pub owner_value: String,
    pub frr_tag: u32,
}

impl Default for Backend {
    fn default() -> Self {
        Backend {
            kind: BackendKind::Linux,
            table: 254,
            protocol: 196,
            metric: 100,
            region: None,
            route_table_id: None,
            owner_tag: "route-discovery".into(),
            owner_value: "managed".into(),
            frr_tag: 186,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub routes: Vec<Route>,
    pub health: Health,
    pub backend: Backend,
    pub local_asn: u32,
    pub reconcile_interval: f64,
    pub state_dir: PathBuf,
    pub listen: IpAddr,
    pub port: u16,
}

impl Config {
    pub fn new(routes: Vec<Route>) -> Self {
        Config {
            routes,
            health: Health::default(),
            backend: Backend::default(),
            local_asn: 65000,
            reconcile_interval: 1.0,
            state_dir: "/var/lib/route-discovery".into(),
            listen: IpAddr::from([127, 0, 0, 1]),
            port: 9808,
        }
    }
}

const HEALTH_KEYS: &[&str] = &[
    "interval",
    "timeout",
    "failures",
    "successes",
    "failback_delay",
    "stale_after",
    "dampening_half_life",
    "dampening_penalty",
    "dampening_suppress",
    "dampening_reuse",
    "dampening_max",
];
const BACKEND_KEYS: &[&str] =
    &["kind", "table", "protocol", "metric", "region", "route_table_id", "owner_tag", "owner_value", "frr_tag"];
const CANDIDATE_KEYS: &[&str] =
    &["id", "probes", "quorum", "gateway", "device", "aws_target", "local_pref", "as_path", "med", "cost", "enabled"];
const PROBE_KEYS: &[&str] = &["host", "port", "source", "device", "mark", "external_path"];
/// Linux route protocols already claimed by kernel, routing daemons or common tools.
const RESERVED_PROTOCOLS: &[u8] = &[1, 2, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 42, 99, 186, 187, 188, 189, 192];
const U32_MAX: i64 = u32::MAX as i64;

pub fn load(path: impl AsRef<Path>) -> Result<Config> {
    parse(&read_toml(path.as_ref())?)
}

pub fn read_toml(path: &Path) -> Result<Table> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    text.parse::<Table>().map_err(|e| Error::Config(format!("{}: {e}", path.display())))
}

fn parse_health(raw: &Table) -> Result<Health> {
    check_keys(raw, HEALTH_KEYS, "health")?;
    let d = Health::default();
    let f = |key: &str, default: f64, low: f64, high: f64| float(raw.get(key), default, &format!("health.{key}"), low, high);
    let i = |key: &str, default: u32| int(raw.get(key), default.into(), &format!("health.{key}"), 1, 1000).map(|v| v as u32);
    let h = Health {
        interval: f("interval", d.interval, 0.01, 86400.0)?,
        timeout: f("timeout", d.timeout, 0.01, 86400.0)?,
        failures: i("failures", d.failures)?,
        successes: i("successes", d.successes)?,
        failback_delay: f("failback_delay", d.failback_delay, 0.0, 1e6)?,
        stale_after: f("stale_after", d.stale_after, 0.01, 86400.0)?,
        dampening_half_life: f("dampening_half_life", d.dampening_half_life, 0.01, 86400.0)?,
        dampening_penalty: f("dampening_penalty", d.dampening_penalty, 0.0, 1e6)?,
        dampening_suppress: f("dampening_suppress", d.dampening_suppress, 0.0, 1e6)?,
        dampening_reuse: f("dampening_reuse", d.dampening_reuse, 0.0, 1e6)?,
        dampening_max: f("dampening_max", d.dampening_max, 0.01, 86400.0)?,
    };
    if h.timeout > h.interval || h.stale_after <= h.interval + h.timeout {
        return config_err("timeout must be <= interval; stale_after must exceed interval + timeout");
    }
    if !(0.0 < h.dampening_reuse && h.dampening_reuse < h.dampening_suppress) {
        return config_err("dampening thresholds require 0 < reuse < suppress");
    }
    Ok(h)
}

fn parse_backend(raw: &Table) -> Result<Backend> {
    check_keys(raw, BACKEND_KEYS, "backend")?;
    let d = Backend::default();
    let kind = match raw.get("kind").map(Value::as_str) {
        None => BackendKind::Linux,
        Some(Some("linux")) => BackendKind::Linux,
        Some(Some("aws")) => BackendKind::Aws,
        Some(Some("frr")) => BackendKind::Frr,
        Some(_) => return config_err("backend.kind must be linux, aws, or frr"),
    };
    let table = int(raw.get("table"), d.table.into(), "backend.table", 1, U32_MAX)? as u32;
    if table == 253 || table == 255 {
        return config_err("cannot manage Linux local/default tables");
    }
    let protocol = int(raw.get("protocol"), d.protocol.into(), "backend.protocol", 1, 255)? as u8;
    if kind == BackendKind::Linux && RESERVED_PROTOCOLS.contains(&protocol) {
        return config_err("choose an unused Linux route protocol, e.g. 196");
    }
    let metric = int(raw.get("metric"), d.metric.into(), "backend.metric", 1, U32_MAX)? as u32;
    let frr_tag = int(raw.get("frr_tag"), d.frr_tag.into(), "backend.frr_tag", 1, U32_MAX)? as u32;
    let region = optional_string(raw.get("region"), "AWS backend requires region")?;
    let route_table_id = optional_string(raw.get("route_table_id"), "AWS backend requires route_table_id")?;
    let owner_tag = optional_string(raw.get("owner_tag"), "backend.owner_tag must be a string")?.unwrap_or(d.owner_tag);
    let owner_value = optional_string(raw.get("owner_value"), "backend.owner_value must be a string")?.unwrap_or(d.owner_value);
    if kind == BackendKind::Aws {
        if !region.as_deref().is_some_and(is_region) {
            return config_err("AWS backend requires region");
        }
        if !route_table_id.as_deref().is_some_and(|id| is_resource(id, "rtb")) {
            return config_err("AWS backend requires route_table_id");
        }
        if owner_tag.is_empty() || owner_value.is_empty() {
            return config_err("AWS route table ownership tag and value must be nonempty");
        }
    }
    Ok(Backend { kind, table, protocol, metric, region, route_table_id, owner_tag, owner_value, frr_tag })
}

fn interface(value: Option<&Value>, message: &str) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(Value::String(s)) if is_interface(s) => Ok(Some(s.clone())),
        Some(_) => config_err(message),
    }
}

fn parse_probe(raw: &Value, b: &Backend, net: IpNet, device: &Option<String>, gateway: Option<IpAddr>) -> Result<Probe> {
    let p = table(raw, "probe")?;
    check_keys(p, PROBE_KEYS, "probe")?;
    let host = address(p.get("host"), "probe.host")?;
    let port = required_int(p.get("port"), "probe.port", 1, 65535)? as u16;
    let source = p.get("source").map(|v| address(Some(v), "probe.source")).transpose()?;
    if source.is_some_and(|s| !same_family(s, host)) {
        return config_err("probe source and host families differ");
    }
    let mark = p.get("mark").map(|v| int(Some(v), 0, "probe.mark", 1000, 30000)).transpose()?.map(|m| m as u32);
    if mark == Some(b.table) {
        return config_err("probe mark/table must differ from managed route table");
    }
    let pdev = match p.get("device") {
        Some(v) => interface(Some(v), "invalid probe.device")?,
        None => device.clone(),
    };
    let external = optional_string(p.get("external_path"), "probe.external_path must be a string")?;
    if b.kind == BackendKind::Aws {
        if external.as_deref().is_none_or(|e| e.trim().is_empty()) {
            return config_err("AWS probes require external_path documenting a path-specific endpoint/vantage point");
        }
    } else {
        if mark.is_none() || host.is_ipv4() != net.addr().is_ipv4() || pdev != *device {
            return config_err("Linux/FRR probes need mark, candidate device, and matching IP family");
        }
        if Some(host) == gateway {
            return config_err("probe an endpoint beyond the gateway to test forwarding");
        }
    }
    Ok(Probe { host, port, source, device: pdev, mark, external_path: external })
}

fn parse_candidate(
    raw: &Value,
    b: &Backend,
    net: IpNet,
    prefix: &str,
    ids: &mut HashSet<String>,
    hops: &mut HashSet<(Option<IpAddr>, Option<String>, Option<String>)>,
    marks: &mut HashSet<u32>,
) -> Result<Candidate> {
    let c = table(raw, &format!("candidate in {prefix}"))?;
    check_keys(c, CANDIDATE_KEYS, &format!("candidate in {prefix}"))?;
    let id = name(c.get("id"), "candidate.id")?;
    if !ids.insert(id.clone()) {
        return config_err(format!("{prefix}: duplicate candidate {id}"));
    }
    let gateway = c.get("gateway").map(|v| address(Some(v), "gateway")).transpose()?;
    let device = interface(c.get("device"), "Linux/FRR candidates need a valid interface name")?;
    if b.kind != BackendKind::Aws {
        if gateway.is_some_and(|g| g.is_ipv4() != net.addr().is_ipv4()) {
            return config_err("gateway and destination families differ");
        }
        if device.is_none() {
            return config_err("Linux/FRR candidates need a valid interface name");
        }
    }
    let target = optional_string(c.get("aws_target"), "AWS candidates require an ENI aws_target")?;
    if b.kind == BackendKind::Aws && !target.as_deref().is_some_and(|t| is_resource(t, "eni")) {
        return config_err("AWS candidates require an ENI aws_target");
    }
    if !hops.insert((gateway, device.clone(), target.clone())) {
        return config_err("candidate next hops must be distinct");
    }
    let entries = match c.get("probes") {
        None => &Vec::new(),
        Some(v) => array(Some(v), &format!("{id}: configure 1–8 probes"))?,
    };
    if !(1..=8).contains(&entries.len()) {
        return config_err(format!("{id}: configure 1–8 probes"));
    }
    let probes = entries.iter().map(|p| parse_probe(p, b, net, &device, gateway)).collect::<Result<Vec<_>>>()?;
    let candidate_marks: HashSet<u32> = probes.iter().filter_map(|p| p.mark).collect();
    if !marks.is_disjoint(&candidate_marks) {
        return config_err("each candidate must have independent probe marks/tables");
    }
    marks.extend(candidate_marks);
    let distinct: HashSet<_> = probes.iter().map(|p| (p.host, p.port, p.source, p.device.clone(), p.mark)).collect();
    if distinct.len() != probes.len() {
        return config_err("duplicate probes cannot count towards quorum");
    }
    let quorum = int(c.get("quorum"), probes.len() as i64, "quorum", 1, probes.len() as i64)? as usize;
    let attr = |key: &str, default: i64| int(c.get(key), default, key, 0, U32_MAX).map(|v| v as u32);
    let (local_pref, med, cost) = (attr("local_pref", 100)?, attr("med", 0)?, attr("cost", 0)?);
    let as_path = match c.get("as_path") {
        None => Vec::new(),
        Some(v) => {
            let values = array(Some(v), "as_path must be an array of <=255 ASNs")?;
            if values.len() > 255 {
                return config_err("as_path must be an array of <=255 ASNs");
            }
            values.iter().map(|a| int(Some(a), 0, "AS number", 1, U32_MAX).map(|v| v as u32)).collect::<Result<_>>()?
        }
    };
    let enabled = boolean(c.get("enabled"), true, "enabled must be a boolean")?;
    Ok(Candidate { id, probes, quorum, gateway, device, aws_target: target, local_pref, as_path, med, cost, enabled })
}

fn parse_route(raw: &Value, b: &Backend, prefixes: &mut HashSet<IpNet>, marks: &mut HashSet<u32>) -> Result<Route> {
    let r = table(raw, "route")?;
    check_keys(r, &["prefix", "candidates", "max_paths", "preempt", "all_down"], "route")?;
    let net = r
        .get("prefix")
        .and_then(Value::as_str)
        .and_then(parse_network)
        .map_or_else(|| config_err("route.prefix must be a canonical IPv4/IPv6 network"), Ok)?;
    let prefix = net.to_string();
    if !prefixes.insert(net) {
        return config_err(format!("duplicate prefix {prefix}"));
    }
    let entries = match r.get("candidates") {
        None => &Vec::new(),
        Some(v) => array(Some(v), &format!("{prefix}: configure 1–32 candidates"))?,
    };
    if !(1..=32).contains(&entries.len()) {
        return config_err(format!("{prefix}: configure 1–32 candidates"));
    }
    let (mut ids, mut hops) = (HashSet::new(), HashSet::new());
    let candidates =
        entries.iter().map(|c| parse_candidate(c, b, net, &prefix, &mut ids, &mut hops, marks)).collect::<Result<Vec<_>>>()?;
    let max_paths = int(r.get("max_paths"), 1, "max_paths", 1, candidates.len() as i64)? as usize;
    if b.kind == BackendKind::Aws && max_paths != 1 {
        return config_err("AWS route-table backend supports one next hop per prefix");
    }
    if b.kind == BackendKind::Linux && net.addr().is_ipv6() && max_paths > 1 && candidates.iter().any(|c| c.gateway.is_none()) {
        return config_err("Linux IPv6 ECMP requires an explicit gateway on every candidate");
    }
    let all_down = match r.get("all_down").map(Value::as_str) {
        None | Some(Some("withdraw")) => AllDown::Withdraw,
        Some(Some("retain")) => AllDown::Retain,
        Some(Some("unreachable")) if b.kind == BackendKind::Linux => AllDown::Unreachable,
        _ if b.kind == BackendKind::Linux => return config_err("all_down must be one of retain, unreachable, withdraw"),
        _ => return config_err("all_down must be one of retain, withdraw"),
    };
    let preempt = boolean(r.get("preempt"), true, "preempt must be a boolean")?;
    Ok(Route { prefix: net, candidates, max_paths, preempt, all_down })
}

pub fn parse(raw: &Table) -> Result<Config> {
    check_keys(raw, &["routes", "health", "backend", "daemon"], "config")?;
    let empty = Table::new();
    let daemon = sub_table(raw, "daemon", &empty)?;
    check_keys(daemon, &["local_asn", "reconcile_interval", "state_dir", "listen", "port"], "daemon")?;
    let health = parse_health(sub_table(raw, "health", &empty)?)?;
    let backend = parse_backend(sub_table(raw, "backend", &empty)?)?;
    let local_asn = int(daemon.get("local_asn"), 65000, "local_asn", 1, U32_MAX)? as u32;
    let entries = match raw.get("routes") {
        None => &Vec::new(),
        Some(v) => array(Some(v), "configure 1–256 routes")?,
    };
    if !(1..=256).contains(&entries.len()) {
        return config_err("configure 1–256 routes");
    }
    let (mut prefixes, mut marks) = (HashSet::new(), HashSet::new());
    let routes = entries.iter().map(|r| parse_route(r, &backend, &mut prefixes, &mut marks)).collect::<Result<Vec<_>>>()?;
    let reconcile_interval = float(daemon.get("reconcile_interval"), 1.0, "reconcile_interval", 0.05, 3600.0)?;
    let listen = match daemon.get("listen") {
        None => IpAddr::from([127, 0, 0, 1]),
        v => address(v, "listen")?,
    };
    let port = int(daemon.get("port"), 9808, "port", 0, 65535)? as u16;
    let state_dir = match daemon.get("state_dir") {
        None => PathBuf::from("/var/lib/route-discovery"),
        Some(Value::String(s)) if Path::new(s).is_absolute() => PathBuf::from(s),
        Some(_) => return config_err("state_dir must be an absolute path"),
    };
    if routes.iter().flat_map(|r| &r.candidates).map(|c| c.probes.len()).sum::<usize>() > 1024 {
        return config_err("at most 1024 probes are supported per process");
    }
    Ok(Config { routes, health, backend, local_asn, reconcile_interval, state_dir, listen, port })
}
