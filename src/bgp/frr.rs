//! bgpd configuration for the discovered AWS peerings. This mode owns FRR's bgpd: the rendered
//! file is applied with `frr-reload.py --daemon bgpd`, which removes bgpd lines not in it.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;

use super::discovery::Neighbor;
use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub struct Policy {
    /// Accept a default route from AWS (for example a TGW route to an egress VPC).
    pub accept_default: bool,
    pub maximum_paths: u8,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { accept_default: true, maximum_paths: 4 }
    }
}

#[derive(Clone, Debug)]
pub struct Plan<'a> {
    pub router_id: IpAddr,
    pub neighbors: &'a [Neighbor],
    pub announce: &'a BTreeSet<IpNet>,
    /// Never learned: the VPC's own CIDRs, so a TGW route cannot capture intra-VPC traffic.
    pub vpc_cidrs: &'a [IpNet],
    /// Neighbors that receive no announcements (source/destination check still enabled).
    pub gated: &'a BTreeSet<IpAddr>,
    pub policy: &'a Policy,
}

fn v(net: &IpNet) -> u8 {
    if matches!(net, IpNet::V4(_)) {
        4
    } else {
        6
    }
}

/// Most common local ASN; others use `local-as` per neighbor.
pub fn router_asn(neighbors: &[Neighbor]) -> Option<u32> {
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    for n in neighbors {
        *counts.entry(n.local_asn).or_default() += 1;
    }
    counts.into_iter().max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0))).map(|(asn, _)| asn)
}

pub fn render(plan: &Plan) -> String {
    let mut lines = vec!["! route-discovery bgp: generated from IMDS, EC2 peering resources and local interfaces".to_string()];
    for version in [4u8, 6] {
        let family = if version == 4 { "ip" } else { "ipv6" };
        let any = if version == 4 { "0.0.0.0/0" } else { "::/0" };
        let max = if version == 4 { 32 } else { 128 };
        let out = format!("{family} prefix-list RDB-OUT-V{version}");
        let mut seq = 0;
        let mut next = || {
            seq += 5;
            seq
        };
        for net in plan.announce.iter().filter(|n| v(n) == version) {
            lines.push(format!("{out} seq {} permit {net}", next()));
        }
        lines.push(format!("{out} seq {} deny any", next()));
        let input = format!("{family} prefix-list RDB-IN-V{version}");
        let mut seq = 0;
        let mut next = || {
            seq += 5;
            seq
        };
        for net in plan.vpc_cidrs.iter().chain(plan.announce.iter()).filter(|n| v(n) == version) {
            lines.push(format!("{input} seq {} deny {net} le {max}", next()));
        }
        if !plan.policy.accept_default {
            lines.push(format!("{input} seq {} deny {any}", next()));
        }
        lines.push(format!("{input} seq {} permit {any} le {max}", next()));
        lines.extend([
            "!".into(),
            format!("route-map RDB-IN-V{version} permit 10"),
            format!(" match {family} address prefix-list RDB-IN-V{version}"),
            "exit".into(),
            format!("route-map RDB-OUT-V{version} permit 10"),
            format!(" match {family} address prefix-list RDB-OUT-V{version}"),
            "exit".into(),
        ]);
    }
    lines.extend(["route-map RDB-DENY deny 10".into(), "exit".into(), "!".into()]);
    let Some(asn) = router_asn(plan.neighbors) else {
        return lines.join("\n") + "\n";
    };
    lines.extend([
        format!("router bgp {asn}"),
        format!(" bgp router-id {}", plan.router_id),
        " no bgp default ipv4-unicast".into(),
        " bgp bestpath as-path multipath-relax".into(),
    ]);
    for n in plan.neighbors {
        lines.push(format!(" neighbor {} remote-as {}", n.address, n.remote_asn));
        lines.push(format!(" neighbor {} description {}", n.address, n.resource));
        if n.local_asn != asn {
            lines.push(format!(" neighbor {} local-as {} no-prepend replace-as", n.address, n.local_asn));
        }
        lines.push(format!(" neighbor {} update-source {}", n.address, n.local_address));
        if let Some(hops) = n.multihop {
            lines.push(format!(" neighbor {} ebgp-multihop {hops}", n.address));
        }
        if n.bfd {
            lines.push(format!(" neighbor {} bfd", n.address));
        }
    }
    for version in [4u8, 6] {
        let members: Vec<&Neighbor> = plan.neighbors.iter().filter(|n| n.address.is_ipv4() == (version == 4)).collect();
        if members.is_empty() {
            continue;
        }
        lines.push(format!(" address-family ipv{version} unicast"));
        for net in plan.announce.iter().filter(|n| v(n) == version) {
            lines.push(format!("  network {net}"));
        }
        lines.push(format!("  maximum-paths {}", plan.policy.maximum_paths));
        for n in members {
            let out = if plan.gated.contains(&n.address) { "RDB-DENY".to_string() } else { format!("RDB-OUT-V{version}") };
            lines.extend([
                format!("  neighbor {} activate", n.address),
                format!("  neighbor {} route-map RDB-IN-V{version} in", n.address),
                format!("  neighbor {} route-map {out} out", n.address),
            ]);
        }
        lines.push(" exit-address-family".into());
    }
    lines.push("exit".into());
    lines.join("\n") + "\n"
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Session {
    pub state: String,
    pub received: Option<u64>,
    pub sent: Option<u64>,
}

/// `show bgp summary json`: sessions keyed by neighbor address across both address families.
pub fn parse_summary(data: &Value) -> Result<BTreeMap<String, Session>> {
    let object = data.as_object().ok_or_else(|| Error::Backend("bgp summary: expected an object".into()))?;
    let mut sessions = BTreeMap::new();
    for family in ["ipv4Unicast", "ipv6Unicast"] {
        for (address, peer) in object.get(family).and_then(|f| f["peers"].as_object()).into_iter().flatten() {
            sessions.insert(
                address.clone(),
                Session {
                    state: peer["state"].as_str().unwrap_or("unknown").to_string(),
                    received: peer["pfxRcd"].as_u64(),
                    sent: peer["pfxSnt"].as_u64(),
                },
            );
        }
    }
    Ok(sessions)
}
