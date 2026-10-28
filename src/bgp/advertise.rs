//! Prefixes this instance announces: addresses on its interfaces that the VPC does not already route.
//!
//! An address inside a VPC CIDR is reached through the VPC local route; announcing it cannot
//! steer traffic. Service addresses (VIPs on `lo` or a dummy interface, secondary ranges outside
//! the VPC) are the ones BGP makes reachable and fails over.

use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;

use super::metadata::Host;
use crate::error::{Error, Result};
use crate::mesh::inventory::{Filter, DEFAULT_EXCLUDE};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Withheld {
    pub prefix: IpNet,
    pub interface: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Announcements {
    pub prefixes: BTreeSet<IpNet>,
    pub withheld: Vec<Withheld>,
}

/// Container and bridge subnets stay local; `lo` is included because it carries service VIPs.
pub fn default_filter() -> Filter {
    Filter { include: vec![], exclude: DEFAULT_EXCLUDE.iter().filter(|p| **p != "lo").map(|p| p.to_string()).collect() }
}

fn routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => !(a.is_loopback() || a.is_link_local() || a.is_unspecified() || a.is_multicast()),
        IpAddr::V6(a) => !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_unicast_link_local()),
    }
}

pub fn select(data: &Value, filter: &Filter, host: &Host) -> Result<Announcements> {
    let links = data.as_array().ok_or_else(|| Error::Backend("ip -json addr: expected an array".into()))?;
    let mut out = Announcements::default();
    for link in links {
        let name = link["ifname"].as_str().unwrap_or_default();
        // Our own GRE inside /29s are link addressing, not services.
        if name.starts_with(super::gre::PREFIX) || filter.excludes(name) {
            continue;
        }
        let up = link["flags"].as_array().into_iter().flatten().any(|f| f == "UP");
        for info in link["addr_info"].as_array().into_iter().flatten() {
            let (Some(local), Some(length)) = (info["local"].as_str(), info["prefixlen"].as_u64()) else { continue };
            let Ok(address) = local.parse::<IpAddr>() else { continue };
            let Ok(net) = IpNet::new(address, length as u8).map(|n| n.trunc()) else { continue };
            if !routable(address) {
                continue;
            }
            let reason = if !up {
                Some("interface down")
            } else if info["tentative"].as_bool() == Some(true) || info["dadfailed"].as_bool() == Some(true) {
                Some("address not yet usable")
            } else if host.in_vpc(&net) {
                Some("inside a VPC CIDR; the VPC local route already reaches it")
            } else {
                None
            };
            match reason {
                Some(reason) => out.withheld.push(Withheld { prefix: net, interface: name.to_string(), reason: reason.into() }),
                None => {
                    out.prefixes.insert(net);
                }
            }
        }
    }
    let prefixes = out.prefixes.clone();
    out.withheld.retain(|w| !prefixes.contains(&w.prefix));
    Ok(out)
}
