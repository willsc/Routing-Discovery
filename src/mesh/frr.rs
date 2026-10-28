//! FRR babeld adapter. This mode owns FRR's `router babel` networks/redistribution and the RDM-* prefix lists.
//!
//! Filters are double-buffered (RDM-*-A / RDM-*-B): a new generation is written completely, the
//! distribute-list is switched to it, then the old one is deleted. Babel never sees a partial filter.

use std::collections::{BTreeMap, BTreeSet};

use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;

use super::inventory::{Inventory, Medium};
use crate::commands::{argv, Runner};
use crate::error::{backend_err, Error, Result};

pub const REDISTRIBUTE: [&str; 2] = ["redistribute ipv4 connected", "redistribute ipv6 connected"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    fn word(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
}

/// (direction, IP version)
pub type Filter = (Direction, u8);
pub const FILTERS: [Filter; 4] = [(Direction::In, 4), (Direction::In, 6), (Direction::Out, 4), (Direction::Out, 6)];

fn family(v: u8) -> &'static str {
    if v == 4 {
        "ip"
    } else {
        "ipv6"
    }
}

fn list_name((direction, v): Filter, generation: char) -> String {
    format!("RDM-{}-V{v}-{generation}", direction.word().to_uppercase())
}

fn distribute((direction, v): Filter, name: &str) -> String {
    let prefix = if v == 4 { "" } else { "ipv6 " };
    format!("{prefix}distribute-list prefix {name} {}", direction.word())
}

fn version(net: &IpNet) -> u8 {
    if matches!(net, IpNet::V4(_)) {
        4
    } else {
        6
    }
}

/// Exact match for a host or published subnet, otherwise any more-specific route.
fn spec(net: &IpNet, exact: bool) -> String {
    let maximum = net.max_prefix_len();
    if exact || net.prefix_len() == maximum {
        net.to_string()
    } else {
        format!("{net} le {maximum}")
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    /// Supernets accepted from, and re-advertised to, neighbours.
    pub accept: Vec<IpNet>,
    pub hello_interval_ms: u32,
    pub update_interval_ms: u32,
}

pub const DEFAULT_ACCEPT: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"];

impl Default for Policy {
    fn default() -> Self {
        Policy {
            accept: DEFAULT_ACCEPT.iter().map(|p| p.parse().unwrap()).collect(),
            hello_interval_ms: 1000,
            update_interval_ms: 4000,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Desired {
    pub networks: BTreeSet<String>,
    pub filters: BTreeMap<Filter, Vec<String>>,
    pub interfaces: BTreeMap<String, Vec<String>>,
}

pub fn desired(inventory: &Inventory, policy: &Policy) -> Desired {
    let published = inventory.prefixes();
    let mut filters: BTreeMap<Filter, Vec<String>> = FILTERS.iter().map(|f| (*f, vec![])).collect();
    for (direction, v) in FILTERS {
        let entries = filters.get_mut(&(direction, v)).unwrap();
        if direction == Direction::Out {
            // Withheld subnets would otherwise leak through `redistribute connected` and the accept supernets.
            entries.extend(inventory.withheld.iter().filter(|n| version(n) == v).map(|n| format!("deny {}", spec(n, true))));
            entries.extend(published.iter().filter(|n| version(n) == v).map(|n| format!("permit {}", spec(n, true))));
        }
        entries.extend(policy.accept.iter().filter(|n| version(n) == v).map(|n| format!("permit {}", spec(n, false))));
        entries.push("deny any".into());
    }
    let interfaces = inventory
        .nics
        .iter()
        .map(|nic| {
            let medium = match nic.medium {
                Medium::Wired => "babel wired",
                Medium::Wireless => "babel wireless",
            };
            let lines = vec![
                medium.to_string(),
                format!("babel hello-interval {}", policy.hello_interval_ms),
                format!("babel update-interval {}", policy.update_interval_ms),
            ];
            (nic.name.clone(), lines)
        })
        .collect();
    Desired { networks: inventory.nics.iter().map(|n| n.name.clone()).collect(), filters, interfaces }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Running {
    pub router: bool,
    pub networks: BTreeSet<String>,
    pub redistribute: BTreeSet<String>,
    /// Active prefix-list name per filter, from `distribute-list` lines.
    pub active: BTreeMap<Filter, String>,
    /// RDM-* prefix lists, entries in sequence order.
    pub lists: BTreeMap<String, Vec<String>>,
    pub interfaces: BTreeMap<String, BTreeSet<String>>,
}

fn parse_filter(words: &[&str]) -> Option<(Filter, String)> {
    let (v, rest) = match words {
        ["ipv6", rest @ ..] => (6, rest),
        rest => (4, rest),
    };
    let ["distribute-list", "prefix", name, direction] = rest else { return None };
    let direction = match *direction {
        "in" => Direction::In,
        "out" => Direction::Out,
        _ => return None,
    };
    Some(((direction, v), name.to_string()))
}

/// Parses `show running-config babeld`; text outside owned stanzas is ignored.
pub fn parse_running(text: &str) -> Running {
    let mut running = Running::default();
    let mut seqs: BTreeMap<String, Vec<(u64, String)>> = BTreeMap::new();
    let mut block: Option<String> = None;
    for raw in text.lines() {
        let indented = raw.starts_with(' ');
        let line = raw.trim();
        if !indented {
            block = None;
        }
        if line.is_empty() || line == "!" || line == "exit" || line == "exit-vrf" {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        if !indented {
            match words.as_slice() {
                ["router", "babel", ..] => {
                    running.router = true;
                    block = Some("router".into());
                }
                ["interface", name, ..] => block = Some(format!("interface {name}")),
                [fam @ ("ip" | "ipv6"), "prefix-list", name, "seq", seq, entry @ ..] if name.starts_with("RDM-") => {
                    let _ = fam;
                    if let Ok(seq) = seq.parse() {
                        seqs.entry(name.to_string()).or_default().push((seq, entry.join(" ")));
                    }
                }
                _ => {}
            }
            continue;
        }
        match block.as_deref() {
            Some("router") => {
                if let ["network", name] = words.as_slice() {
                    running.networks.insert(name.to_string());
                } else if REDISTRIBUTE.contains(&line) {
                    running.redistribute.insert(line.to_string());
                } else if let Some((filter, name)) = parse_filter(&words) {
                    running.active.insert(filter, name);
                }
            }
            Some(interface) if line.starts_with("babel ") => {
                let name = interface.trim_start_matches("interface ").to_string();
                running.interfaces.entry(name).or_default().insert(line.to_string());
            }
            _ => {}
        }
    }
    for (name, mut entries) in seqs {
        entries.sort();
        running.lists.insert(name, entries.into_iter().map(|(_, e)| e).collect());
    }
    running
}

/// vtysh commands, after `configure terminal`, that move `running` to `desired`; empty when converged.
pub fn plan(desired: &Desired, running: &Running) -> Vec<String> {
    let mut lists = vec![];
    let mut router = vec![];
    let mut retire = vec![];
    let mut written = BTreeSet::new();
    for (filter, entries) in &desired.filters {
        let current = running.active.get(filter);
        if current.is_some_and(|name| running.lists.get(name) == Some(entries)) {
            continue;
        }
        let generation = if current.is_some_and(|n| n.ends_with("-A")) { 'B' } else { 'A' };
        let name = list_name(*filter, generation);
        let header = format!("{} prefix-list {name}", family(filter.1));
        if running.lists.contains_key(&name) {
            lists.push(format!("no {header}"));
        }
        lists.extend(entries.iter().enumerate().map(|(i, e)| format!("{header} seq {} {e}", (i + 1) * 5)));
        router.push(distribute(*filter, &name));
        written.insert(name);
        if let Some(old) = current.filter(|old| running.lists.contains_key(*old)) {
            retire.push(format!("no {} prefix-list {old}", family(filter.1)));
        }
    }
    // Orphaned generations from an interrupted switch.
    for name in running.lists.keys() {
        if !running.active.values().any(|a| a == name) && !written.contains(name) {
            let fam = if name.contains("-V6-") { "ipv6" } else { "ip" };
            retire.push(format!("no {fam} prefix-list {name}"));
        }
    }
    router.extend(REDISTRIBUTE.iter().filter(|r| !running.redistribute.contains(**r)).map(|r| r.to_string()));
    router.extend(desired.networks.difference(&running.networks).map(|n| format!("network {n}")));
    router.extend(running.networks.difference(&desired.networks).map(|n| format!("no network {n}")));
    let mut interfaces = vec![];
    for (name, lines) in &desired.interfaces {
        let current = running.interfaces.get(name);
        let missing: Vec<&String> = lines.iter().filter(|l| current.is_none_or(|c| !c.contains(*l))).collect();
        if !missing.is_empty() {
            interfaces.push(format!("interface {name}"));
            interfaces.extend(missing.into_iter().cloned());
            interfaces.push("exit".into());
        }
    }
    if lists.is_empty() && router.is_empty() && interfaces.is_empty() && retire.is_empty() {
        return vec![];
    }
    let mut commands = lists;
    // Interface settings first so a new adjacency starts with the intended timers.
    commands.extend(interfaces);
    if !router.is_empty() || !running.router {
        commands.push("router babel".into());
        commands.extend(router);
        commands.push("exit".into());
    }
    commands.extend(retire);
    commands
}

/// Removes this mode's babeld instance and filters. Interface babel settings are inert without it.
pub fn withdraw_plan(running: &Running) -> Vec<String> {
    let mut commands = vec![];
    if running.router {
        commands.push("no router babel".into());
    }
    for name in running.lists.keys() {
        let fam = if name.contains("-V6-") { "ipv6" } else { "ip" };
        commands.push(format!("no {fam} prefix-list {name}"));
    }
    commands
}

/// Full fragment for review or for a fresh frr.conf.
pub fn render(desired: &Desired) -> String {
    let mut lines = vec!["! route-discovery mesh: generated from this host's NIC inventory".to_string()];
    for (filter, entries) in &desired.filters {
        let header = format!("{} prefix-list {}", family(filter.1), list_name(*filter, 'A'));
        lines.extend(entries.iter().enumerate().map(|(i, e)| format!("{header} seq {} {e}", (i + 1) * 5)));
    }
    lines.push("!".into());
    for (name, settings) in &desired.interfaces {
        lines.push(format!("interface {name}"));
        lines.extend(settings.iter().map(|s| format!(" {s}")));
        lines.push("exit".into());
        lines.push("!".into());
    }
    lines.push("router babel".into());
    lines.extend(desired.networks.iter().map(|n| format!(" network {n}")));
    lines.extend(REDISTRIBUTE.iter().map(|r| format!(" {r}")));
    lines.extend(FILTERS.iter().map(|f| format!(" {}", distribute(*f, &list_name(*f, 'A')))));
    lines.push("exit".into());
    lines.join("\n") + "\n"
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MeshRoute {
    pub prefix: String,
    pub next_hops: Vec<String>,
}

/// Selected Babel routes from zebra's `show ip[v6] route babel json`.
pub fn parse_routes(data: &Value) -> Result<Vec<MeshRoute>> {
    let object = data.as_object().ok_or_else(|| Error::Backend("babel routes: expected an object".into()))?;
    let mut routes = vec![];
    for (prefix, entries) in object {
        for entry in entries.as_array().into_iter().flatten() {
            if entry["selected"].as_bool() != Some(true) {
                continue;
            }
            let next_hops = entry["nexthops"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|h| h["active"].as_bool() == Some(true))
                .map(|h| {
                    let via = h["ip"].as_str().unwrap_or("directly");
                    let dev = h["interfaceName"].as_str().unwrap_or("?");
                    format!("{via} dev {dev}")
                })
                .collect();
            routes.push(MeshRoute { prefix: prefix.clone(), next_hops });
        }
    }
    Ok(routes)
}

pub struct Vtysh<'a> {
    pub runner: &'a dyn Runner,
    pub socket_dir: Option<&'a str>,
}

impl Vtysh<'_> {
    fn base(&self) -> Vec<String> {
        let mut args = argv(["vtysh"]);
        if let Some(dir) = self.socket_dir {
            args.extend(argv(["--vty_socket", dir]));
        }
        args
    }

    pub async fn show(&self, command: &str) -> Result<String> {
        let mut args = self.base();
        args.extend(argv(["-c", command]));
        self.runner.run(&args, 5.0).await
    }

    pub async fn running(&self) -> Result<Running> {
        let text = self.show("show running-config babeld").await?;
        Ok(parse_running(&text))
    }

    pub async fn configure(&self, commands: &[String]) -> Result<()> {
        if commands.is_empty() {
            return Ok(());
        }
        let mut args = self.base();
        args.extend(argv(["-c", "configure terminal"]));
        for command in commands {
            args.extend(argv(["-c", command.as_str()]));
        }
        self.runner.run(&args, 10.0).await.map(|_| ())
    }

    pub async fn routes(&self) -> Result<Vec<MeshRoute>> {
        let mut routes = vec![];
        for family in ["ip", "ipv6"] {
            let text = self.show(&format!("show {family} route babel json")).await?;
            let data: Value = serde_json::from_str(&text).map_err(|_| Error::Backend("babel routes: non-JSON output".into()))?;
            routes.extend(parse_routes(&data)?);
        }
        Ok(routes)
    }

    /// FRR babeld has no JSON neighbour view; lines are reported verbatim.
    pub async fn neighbours(&self) -> Result<Vec<String>> {
        let text = self.show("show babel neighbor").await?;
        Ok(text.lines().map(str::trim).filter(|l| l.starts_with("Neighbour")).map(str::to_string).collect())
    }
}

pub fn ensure_converged(desired: &Desired, running: &Running) -> Result<()> {
    let remaining = plan(desired, running);
    if remaining.is_empty() {
        Ok(())
    } else {
        backend_err(format!("FRR running config does not reflect: {}", remaining.join("; ")))
    }
}
