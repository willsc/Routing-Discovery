//! Local NIC inventory from `ip -json addr show`. Nothing here is configured per host.

use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;

use crate::commands::{argv, Runner};
use crate::error::{Error, Result};

/// Container, bridge and CNI plumbing is local; publishing it would leak host-private subnets.
pub const DEFAULT_EXCLUDE: &[&str] = &[
    "lo",
    "docker*",
    "br-*",
    "veth*",
    "virbr*",
    "cni*",
    "flannel*",
    "cali*",
    "vxlan.calico",
    "kube-*",
    "cilium*",
    "lxc*",
    "podman*",
    "tap*",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Medium {
    Wired,
    Wireless,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Nic {
    pub name: String,
    pub medium: Medium,
    /// Connected subnets this node publishes into the mesh.
    pub prefixes: Vec<IpNet>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Inventory {
    pub nics: Vec<Nic>,
    pub skipped: Vec<Skipped>,
    /// Subnets on skipped interfaces; filtered so they are never advertised.
    pub withheld: Vec<IpNet>,
}

impl Inventory {
    pub fn prefixes(&self) -> BTreeSet<IpNet> {
        self.nics.iter().flat_map(|n| n.prefixes.iter().copied()).collect()
    }
}

#[derive(Clone, Debug)]
pub struct Filter {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl Default for Filter {
    fn default() -> Self {
        Filter { include: vec![], exclude: DEFAULT_EXCLUDE.iter().map(|s| s.to_string()).collect() }
    }
}

/// `*` matches any run of characters; everything else is literal.
pub fn glob(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !name.starts_with(first) || name.len() < first.len() + last.len() || !name.ends_with(last) {
        return false;
    }
    let mut rest = &name[first.len()..name.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(i) => rest = &rest[i + part.len()..],
            None => return false,
        }
    }
    true
}

impl Filter {
    pub fn excludes(&self, name: &str) -> bool {
        self.reason(name).is_some()
    }

    /// An explicit include wins over the default exclusions.
    fn reason(&self, name: &str) -> Option<String> {
        if !self.include.is_empty() {
            return (!self.include.iter().any(|p| glob(p, name))).then(|| "not matched by --include".into());
        }
        self.exclude.iter().find(|p| glob(p, name)).map(|p| format!("excluded by pattern {p}"))
    }
}

/// Addresses that cannot be reached from another node are never published.
fn publishable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => !(a.is_loopback() || a.is_link_local() || a.is_unspecified() || a.is_multicast()),
        IpAddr::V6(a) => !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_unicast_link_local()),
    }
}

fn skip(name: &str, reason: impl Into<String>) -> Skipped {
    Skipped { name: name.to_string(), reason: reason.into() }
}

/// (has an IPv6 link-local address, publishable connected subnets)
fn addresses(link: &Value) -> (bool, Vec<IpNet>) {
    let mut link_local = false;
    let mut prefixes = BTreeSet::new();
    for info in link["addr_info"].as_array().into_iter().flatten() {
        let (Some(local), Some(length)) = (info["local"].as_str(), info["prefixlen"].as_u64()) else { continue };
        let Ok(address) = local.parse::<IpAddr>() else { continue };
        if let IpAddr::V6(a) = address {
            link_local |= a.is_unicast_link_local();
        }
        if info["tentative"].as_bool() == Some(true) || info["dadfailed"].as_bool() == Some(true) || !publishable(address) {
            continue;
        }
        if let Ok(net) = IpNet::new(address, length as u8) {
            prefixes.insert(net.trunc());
        }
    }
    (link_local, prefixes.into_iter().collect())
}

fn classify(link: &Value, filter: &Filter, wireless: &dyn Fn(&str) -> bool) -> std::result::Result<Nic, Skipped> {
    let name = link["ifname"].as_str().unwrap_or_default();
    let flags: BTreeSet<&str> = link["flags"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    if let Some(reason) = filter.reason(name) {
        return Err(skip(name, reason));
    }
    if flags.contains("LOOPBACK") {
        return Err(skip(name, "loopback"));
    }
    if let Some(master) = link["master"].as_str() {
        return Err(skip(name, format!("member of {master}; the aggregate carries the mesh")));
    }
    if !flags.contains("UP") || link["operstate"].as_str() == Some("DOWN") || flags.contains("NO-CARRIER") {
        return Err(skip(name, "link down"));
    }
    if !flags.contains("MULTICAST") {
        return Err(skip(name, "no MULTICAST flag; Babel hellos use ff02::1:6"));
    }
    let (link_local, prefixes) = addresses(link);
    if !link_local {
        return Err(skip(name, "no IPv6 link-local address; Babel cannot form adjacencies"));
    }
    let medium = if wireless(name) { Medium::Wireless } else { Medium::Wired };
    Ok(Nic { name: name.to_string(), medium, prefixes })
}

pub fn parse(data: &Value, filter: &Filter, wireless: &dyn Fn(&str) -> bool) -> Result<Inventory> {
    let links = data.as_array().ok_or_else(|| Error::Backend("ip -json addr: expected an array".into()))?;
    let mut inventory = Inventory::default();
    for link in links {
        if link["ifname"].as_str().is_none_or(str::is_empty) {
            return Err(Error::Backend("ip -json addr: link without ifname".into()));
        }
        match classify(link, filter, wireless) {
            Ok(nic) => inventory.nics.push(nic),
            Err(skipped) => {
                inventory.withheld.extend(addresses(link).1);
                inventory.skipped.push(skipped);
            }
        }
    }
    let published = inventory.prefixes();
    inventory.withheld.retain(|n| !published.contains(n));
    inventory.withheld.sort();
    inventory.withheld.dedup();
    inventory.nics.sort_by(|a, b| a.name.cmp(&b.name));
    inventory.skipped.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(inventory)
}

fn sysfs_wireless(name: &str) -> bool {
    std::path::Path::new("/sys/class/net").join(name).join("wireless").exists()
}

pub async fn collect(runner: &dyn Runner, filter: &Filter) -> Result<Inventory> {
    let output = runner.run(&argv(["ip", "-json", "addr", "show"]), 3.0).await?;
    let data: Value = serde_json::from_str(&output).map_err(|_| Error::Backend("ip -json addr: non-JSON output".into()))?;
    parse(&data, filter, &sysfs_wireless)
}
