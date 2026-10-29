//! GRE tunnels to selected peers. Only interfaces named `rdm*` are owned.
//!
//! Each tunnel gets the MULTICAST flag and a fixed IPv6 link-local address, which is all Babel
//! needs to form an adjacency over it; the mesh inventory then picks it up like any other link.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;

use super::registry::Entry;
use crate::commands::argv;
use crate::error::{Error, Result};
use crate::hash::fnv1a;

pub const PREFIX: &str = "rdm";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Tunnel {
    pub name: String,
    pub peer: String,
    pub local: Ipv4Addr,
    pub remote: Ipv4Addr,
}

/// `rdm` plus 8 hex digits of the peer's host ID: 11 bytes, within IFNAMSIZ.
pub fn tunnel_name(peer: &str) -> String {
    format!("{PREFIX}{:08x}", fnv1a(peer.as_bytes()))
}

/// This host's link-local address on every tunnel, derived from its host ID.
pub fn link_local(host: &str) -> Ipv6Addr {
    let (a, b) = (fnv1a(host.as_bytes()), fnv1a(format!("{host}/link-local").as_bytes()));
    Ipv6Addr::new(0xfe80, 0, 0, 0, (a >> 16) as u16, a as u16, (b >> 16) as u16, b as u16)
}

/// Tunnels for `peers`; a peer whose name collides with an earlier one is reported and skipped.
pub fn desired(local: Ipv4Addr, peers: &[Entry]) -> (Vec<Tunnel>, Vec<String>) {
    let mut tunnels: Vec<Tunnel> = vec![];
    let mut skipped = vec![];
    for peer in peers {
        let name = tunnel_name(&peer.host);
        if let Some(first) = tunnels.iter().find(|t| t.name == name) {
            skipped.push(format!("{}: tunnel name {name} already used for {}", peer.host, first.peer));
            continue;
        }
        tunnels.push(Tunnel { name, peer: peer.host.clone(), local, remote: peer.endpoint });
    }
    (tunnels, skipped)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Existing {
    pub kind: String,
    pub local: Option<Ipv4Addr>,
    pub remote: Option<Ipv4Addr>,
    pub mtu: Option<u32>,
    pub up: bool,
    pub multicast: bool,
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
        let flags: BTreeSet<&str> = link["flags"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        let addresses = link["addr_info"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| IpNet::new(a["local"].as_str()?.parse().ok()?, a["prefixlen"].as_u64()? as u8).ok())
            .collect();
        tunnels.insert(
            name.to_string(),
            Existing {
                kind: link["linkinfo"]["info_kind"].as_str().unwrap_or_default().to_string(),
                local: address("local"),
                remote: address("remote"),
                mtu: link["mtu"].as_u64().and_then(|m| u32::try_from(m).ok()),
                up: flags.contains("UP"),
                multicast: flags.contains("MULTICAST"),
                addresses,
            },
        );
    }
    Ok(tunnels)
}

/// `ip` argv lists that move `existing` to `desired`.
pub fn plan(desired: &[Tunnel], existing: &BTreeMap<String, Existing>, link_local: Ipv6Addr, mtu: u32) -> Vec<Vec<String>> {
    let mut commands = vec![];
    let wanted: BTreeSet<&str> = desired.iter().map(|t| t.name.as_str()).collect();
    for name in existing.keys().filter(|n| !wanted.contains(n.as_str())) {
        commands.push(argv(["ip", "link", "del", name]));
    }
    let address = IpNet::new(link_local.into(), 64).expect("valid prefix length");
    for tunnel in desired {
        let current = existing.get(&tunnel.name);
        let matches =
            current.is_some_and(|c| c.kind == "gre" && c.local == Some(tunnel.local) && c.remote == Some(tunnel.remote));
        let current = current.filter(|_| matches);
        if !matches {
            if existing.contains_key(&tunnel.name) {
                commands.push(argv(["ip", "link", "del", &tunnel.name]));
            }
            let (local, remote) = (tunnel.local.to_string(), tunnel.remote.to_string());
            commands.push(argv([
                "ip",
                "link",
                "add",
                &tunnel.name,
                "type",
                "gre",
                "local",
                &local,
                "remote",
                &remote,
                "ttl",
                "255",
            ]));
        }
        if current.and_then(|c| c.mtu) != Some(mtu) {
            commands.push(argv(["ip", "link", "set", &tunnel.name, "mtu", &mtu.to_string()]));
        }
        if !current.is_some_and(|c| c.multicast) {
            commands.push(argv(["ip", "link", "set", &tunnel.name, "multicast", "on"]));
        }
        if !current.is_some_and(|c| c.addresses.contains(&address)) {
            commands.push(argv(["ip", "addr", "add", &address.to_string(), "dev", &tunnel.name]));
        }
        if !current.is_some_and(|c| c.up) {
            commands.push(argv(["ip", "link", "set", &tunnel.name, "up"]));
        }
    }
    commands
}
