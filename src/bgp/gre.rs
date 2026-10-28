//! GRE tunnels for Transit Gateway Connect peers. Only interfaces named `rdgre*` are owned.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ipnet::IpNet;
use serde_json::Value;

use super::discovery::Gre;
use crate::commands::argv;
use crate::error::{Error, Result};

pub const PREFIX: &str = "rdgre";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Existing {
    pub kind: String,
    pub local: Option<IpAddr>,
    pub remote: Option<IpAddr>,
    pub up: bool,
    pub addresses: BTreeSet<IpNet>,
}

/// Owned tunnels from `ip -d -json addr show`.
pub fn parse(data: &Value) -> Result<BTreeMap<String, Existing>> {
    let links = data.as_array().ok_or_else(|| Error::Backend("ip -d -json addr: expected an array".into()))?;
    let mut tunnels = BTreeMap::new();
    for link in links {
        let Some(name) = link["ifname"].as_str().filter(|n| n.starts_with(PREFIX)) else { continue };
        let info = &link["linkinfo"]["info_data"];
        let address = |key: &str| info[key].as_str().and_then(|a| a.parse().ok());
        let addresses = link["addr_info"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| IpNet::new(a["local"].as_str()?.parse().ok()?, a["prefixlen"].as_u64()? as u8).ok())
            .filter(|n| !matches!(n.addr(), IpAddr::V6(a) if a.is_unicast_link_local()))
            .collect();
        tunnels.insert(
            name.to_string(),
            Existing {
                kind: link["linkinfo"]["info_kind"].as_str().unwrap_or_default().to_string(),
                local: address("local"),
                remote: address("remote"),
                up: link["flags"].as_array().into_iter().flatten().any(|f| f == "UP"),
                addresses,
            },
        );
    }
    Ok(tunnels)
}

fn kind(tunnel: &Gre) -> &'static str {
    if tunnel.local.is_ipv4() {
        "gre"
    } else {
        "ip6gre"
    }
}

/// `ip` argv lists that move `existing` to `desired`.
pub fn plan(desired: &[Gre], existing: &BTreeMap<String, Existing>) -> Vec<Vec<String>> {
    let mut commands = vec![];
    let wanted: BTreeSet<&str> = desired.iter().map(|t| t.name.as_str()).collect();
    for name in existing.keys().filter(|n| !wanted.contains(n.as_str())) {
        commands.push(argv(["ip", "link", "del", name]));
    }
    for tunnel in desired {
        let current = existing.get(&tunnel.name);
        let matches =
            current.is_some_and(|c| c.kind == kind(tunnel) && c.local == Some(tunnel.local) && c.remote == Some(tunnel.remote));
        let (local, remote) = (tunnel.local.to_string(), tunnel.remote.to_string());
        if !matches {
            if current.is_some() {
                commands.push(argv(["ip", "link", "del", &tunnel.name]));
            }
            commands.push(argv([
                "ip",
                "link",
                "add",
                &tunnel.name,
                "type",
                kind(tunnel),
                "local",
                &local,
                "remote",
                &remote,
                "ttl",
                "255",
            ]));
        }
        let have = current.filter(|_| matches).map(|c| c.addresses.clone()).unwrap_or_default();
        let want: BTreeSet<IpNet> = tunnel.inside.iter().copied().collect();
        for net in have.difference(&want) {
            commands.push(argv(["ip", "addr", "del", &net.to_string(), "dev", &tunnel.name]));
        }
        for net in want.difference(&have) {
            commands.push(argv(["ip", "addr", "add", &net.to_string(), "dev", &tunnel.name]));
        }
        if !matches || !current.is_some_and(|c| c.up) {
            commands.push(argv(["ip", "link", "set", &tunnel.name, "up"]));
        }
    }
    commands
}
