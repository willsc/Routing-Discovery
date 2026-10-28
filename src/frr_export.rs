//! FRR fragment that redistributes this daemon's tagged statics into BGP (host `frr` backend).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use crate::config::{BackendKind, Config};
use crate::error::{config_err, Error, Result};

pub fn frr_config(config: &Config, router_id: &str, peer: &str, peer_asn: i64, med: i64) -> Result<String> {
    let router_id: Ipv4Addr = router_id.parse().map_err(|_| Error::Config("router-id must be an IPv4 address".into()))?;
    let peer: IpAddr = peer.parse().map_err(|_| Error::Config("peer must be a literal IP address".into()))?;
    if !(1..=i64::from(u32::MAX)).contains(&peer_asn) || !(0..=i64::from(u32::MAX)).contains(&med) {
        return config_err("invalid peer ASN or MED");
    }
    if config.backend.kind != BackendKind::Frr {
        return config_err("render-frr requires backend.kind=frr");
    }
    let mut lines: Vec<String> = [
        "! Merge this fragment into FRR; enable zebra, staticd, bgpd and bfdd.",
        "! Reserve RD-* policy names and this route tag exclusively for route-discovery.",
        "! No health-dependent static routes should be saved to frr.conf.",
        "route-map RD-IN deny 10",
        "!",
    ]
    .map(String::from)
    .into();
    let version = |v6: bool| if v6 { 6 } else { 4 };
    let families: BTreeSet<u8> = config.routes.iter().map(|r| version(r.is_v6())).collect();
    for &v in &families {
        let cmd = if v == 4 { "ip" } else { "ipv6" };
        for (i, route) in config.routes.iter().filter(|r| version(r.is_v6()) == v).enumerate() {
            lines.push(format!("{cmd} prefix-list RD-V{v} seq {} permit {}", (i + 1) * 10, route.prefix));
        }
        lines.extend([
            format!("route-map RD-STATIC{v} permit 10"),
            format!(" match tag {}", config.backend.frr_tag),
            format!(" match {cmd} address prefix-list RD-V{v}"),
            format!(" set metric {med}"),
            "!".into(),
            format!("route-map RD-OUT{v} permit 10"),
            format!(" match {cmd} address prefix-list RD-V{v}"),
            "!".into(),
        ]);
    }
    lines.extend([
        format!("router bgp {}", config.local_asn),
        format!(" bgp router-id {router_id}"),
        " no bgp default ipv4-unicast".into(),
        format!(" neighbor {peer} remote-as {peer_asn}"),
        format!(" neighbor {peer} bfd"),
    ]);
    for &v in &families {
        lines.extend([
            format!(" address-family ipv{v} unicast"),
            format!("  neighbor {peer} activate"),
            format!("  neighbor {peer} route-map RD-IN in"),
            format!("  neighbor {peer} route-map RD-OUT{v} out"),
            format!("  redistribute static route-map RD-STATIC{v}"),
            " exit-address-family".into(),
        ]);
    }
    Ok(lines.join("\n") + "\n")
}
