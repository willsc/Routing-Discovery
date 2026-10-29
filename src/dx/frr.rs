//! bgpd configuration for Direct Connect VIF sessions. Like the bgp mode, this owns bgpd.

use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::IpNet;

use super::vif::Neighbor;
use crate::bgp::frr::router_asn;

/// AWS limit for prefixes a customer router advertises over a private or transit VIF; beyond it
/// the BGP session goes idle.
pub const VIF_PREFIX_LIMIT: usize = 100;

#[derive(Clone, Debug)]
pub struct Policy {
    pub bfd: bool,
    pub accept_default: bool,
    pub maximum_paths: u8,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { bfd: true, accept_default: false, maximum_paths: 4 }
    }
}

pub struct Plan<'a> {
    pub router_id: IpAddr,
    pub neighbors: &'a [Neighbor],
    pub announce: &'a BTreeSet<IpNet>,
    /// When set, every VIF neighbor gets a deny-all export (for example over the prefix limit).
    pub gated: bool,
    pub policy: &'a Policy,
}

fn v(net: &IpNet) -> u8 {
    if matches!(net, IpNet::V4(_)) {
        4
    } else {
        6
    }
}

pub fn render(plan: &Plan) -> String {
    let mut lines = vec!["! route-discovery dx: generated from the Direct Connect API and local interfaces".to_string()];
    for version in [4u8, 6] {
        let family = if version == 4 { "ip" } else { "ipv6" };
        let any = if version == 4 { "0.0.0.0/0" } else { "::/0" };
        let max = if version == 4 { 32 } else { 128 };
        let mut seq = 0;
        let mut next = || {
            seq += 5;
            seq
        };
        for net in plan.announce.iter().filter(|n| v(n) == version) {
            lines.push(format!("{family} prefix-list RDX-OUT-V{version} seq {} permit {net}", next()));
        }
        lines.push(format!("{family} prefix-list RDX-OUT-V{version} seq {} deny any", next()));
        let mut seq = 0;
        let mut next = || {
            seq += 5;
            seq
        };
        // Never learn on-prem space back from AWS.
        for net in plan.announce.iter().filter(|n| v(n) == version) {
            lines.push(format!("{family} prefix-list RDX-IN-V{version} seq {} deny {net} le {max}", next()));
        }
        if !plan.policy.accept_default {
            lines.push(format!("{family} prefix-list RDX-IN-V{version} seq {} deny {any}", next()));
        }
        lines.push(format!("{family} prefix-list RDX-IN-V{version} seq {} permit {any} le {max}", next()));
        lines.extend([
            "!".into(),
            format!("route-map RDX-IN-V{version} permit 10"),
            format!(" match {family} address prefix-list RDX-IN-V{version}"),
            "exit".into(),
            format!("route-map RDX-OUT-V{version} permit 10"),
            format!(" match {family} address prefix-list RDX-OUT-V{version}"),
            "exit".into(),
        ]);
    }
    lines.extend(["route-map RDX-DENY deny 10".into(), "exit".into(), "!".into()]);
    let Some(asn) = router_asn(plan.neighbors.iter().map(|n| n.local_asn)) else {
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
        lines.push(format!(" neighbor {} description {}", n.address, n.vif));
        if n.local_asn != asn {
            lines.push(format!(" neighbor {} local-as {} no-prepend replace-as", n.address, n.local_asn));
        }
        if let Some(password) = &n.password {
            lines.push(format!(" neighbor {} password {password}", n.address));
        }
        if plan.policy.bfd {
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
        let out = if plan.gated { "RDX-DENY".to_string() } else { format!("RDX-OUT-V{version}") };
        for n in members {
            lines.extend([
                format!("  neighbor {} activate", n.address),
                format!("  neighbor {} route-map RDX-IN-V{version} in", n.address),
                format!("  neighbor {} route-map {out} out", n.address),
                format!("  neighbor {} maximum-prefix-out {VIF_PREFIX_LIMIT}", n.address),
            ]);
        }
        lines.push(" exit-address-family".into());
    }
    lines.push("exit".into());
    lines.join("\n") + "\n"
}
