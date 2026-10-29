//! 802.1Q interfaces for VIFs on mapped ports. Only interfaces named `rddx*` are owned.

use std::collections::{BTreeMap, BTreeSet};

use ipnet::IpNet;
use serde_json::Value;

use super::vif::VlanLink;
use crate::commands::argv;
use crate::error::{Error, Result};

pub const PREFIX: &str = "rddx";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Existing {
    pub parent: Option<String>,
    pub vlan: Option<u16>,
    pub mtu: Option<u32>,
    pub up: bool,
    pub addresses: BTreeSet<IpNet>,
}

/// Owned VLAN links from `ip -d -json addr show`; `link` names the parent.
pub fn parse(data: &Value) -> Result<BTreeMap<String, Existing>> {
    let links = data.as_array().ok_or_else(|| Error::Backend("ip -d -json addr: expected an array".into()))?;
    let mut owned = BTreeMap::new();
    for link in links {
        let Some(name) = link["ifname"].as_str().filter(|n| n.starts_with(PREFIX)) else { continue };
        let vlan = (link["linkinfo"]["info_kind"] == "vlan")
            .then(|| link["linkinfo"]["info_data"]["id"].as_u64().and_then(|v| u16::try_from(v).ok()))
            .flatten();
        let addresses = link["addr_info"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| IpNet::new(a["local"].as_str()?.parse().ok()?, a["prefixlen"].as_u64()? as u8).ok())
            .filter(|n| !matches!(n.addr(), std::net::IpAddr::V6(a) if a.is_unicast_link_local()))
            .collect();
        owned.insert(
            name.to_string(),
            Existing {
                parent: link["link"].as_str().map(str::to_string),
                vlan,
                mtu: link["mtu"].as_u64().and_then(|m| u32::try_from(m).ok()),
                up: link["flags"].as_array().into_iter().flatten().any(|f| f == "UP"),
                addresses,
            },
        );
    }
    Ok(owned)
}

pub fn plan(desired: &[VlanLink], existing: &BTreeMap<String, Existing>) -> Vec<Vec<String>> {
    let mut commands = vec![];
    let wanted: BTreeSet<&str> = desired.iter().map(|l| l.name.as_str()).collect();
    for name in existing.keys().filter(|n| !wanted.contains(n.as_str())) {
        commands.push(argv(["ip", "link", "del", name]));
    }
    for link in desired {
        let current = existing.get(&link.name);
        let matches = current.is_some_and(|c| c.parent.as_deref() == Some(link.parent.as_str()) && c.vlan == Some(link.vlan));
        if !matches {
            if current.is_some() {
                commands.push(argv(["ip", "link", "del", &link.name]));
            }
            let vlan = link.vlan.to_string();
            commands.push(argv(["ip", "link", "add", "link", &link.parent, "name", &link.name, "type", "vlan", "id", &vlan]));
        }
        if let Some(mtu) = link.mtu.filter(|m| !matches || current.and_then(|c| c.mtu) != Some(*m)) {
            commands.push(argv(["ip", "link", "set", &link.name, "mtu", &mtu.to_string()]));
        }
        let have = current.filter(|_| matches).map(|c| c.addresses.clone()).unwrap_or_default();
        let want: BTreeSet<IpNet> = link.addresses.iter().copied().collect();
        for net in have.difference(&want) {
            commands.push(argv(["ip", "addr", "del", &net.to_string(), "dev", &link.name]));
        }
        for net in want.difference(&have) {
            commands.push(argv(["ip", "addr", "add", &net.to_string(), "dev", &link.name]));
        }
        if !matches || !current.is_some_and(|c| c.up) {
            commands.push(argv(["ip", "link", "set", &link.name, "up"]));
        }
    }
    commands
}
