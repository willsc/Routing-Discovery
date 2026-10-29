//! Direct Connect virtual interfaces this router terminates, from the Direct Connect API.
//!
//! A VIF is this router's when a BGP peer's customer address is already configured on a local
//! interface, or when its connection or LAG is mapped to a local port with `--parent`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use async_trait::async_trait;
use ipnet::IpNet;
use serde::Serialize;

use crate::bgp::discovery::Ignored;
use crate::error::Result;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BgpPeer {
    pub id: String,
    pub asn: Option<i64>,
    pub auth_key: Option<String>,
    pub amazon_address: String,
    pub customer_address: String,
    pub state: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Vif {
    pub id: String,
    pub region: String,
    /// dxcon-* or dxlag-*
    pub connection_id: String,
    /// private, transit or public
    pub kind: String,
    pub state: String,
    pub vlan: u16,
    pub amazon_side_asn: Option<i64>,
    pub mtu: Option<u32>,
    pub peers: Vec<BgpPeer>,
}

#[async_trait]
pub trait DirectConnect: Send + Sync {
    async fn virtual_interfaces(&self) -> Result<Vec<Vif>>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Neighbor {
    pub vif: String,
    pub kind: String,
    pub address: IpAddr,
    /// Customer address with the VIF peering prefix length.
    pub local: IpNet,
    pub remote_asn: u32,
    pub local_asn: u32,
    /// MD5 key from the API; never logged or reported.
    #[serde(skip)]
    pub password: Option<String>,
    /// Provisioned VLAN interface, when the VIF arrives on a mapped port.
    pub interface: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VlanLink {
    pub name: String,
    pub parent: String,
    pub vlan: u16,
    pub mtu: Option<u32>,
    pub addresses: Vec<IpNet>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Discovered {
    pub neighbors: Vec<Neighbor>,
    pub links: Vec<VlanLink>,
    pub ignored: Vec<Ignored>,
}

/// VLAN interface for a VIF: `rddx<hhhh>.<vlan>`, where `hhhh` is a stable 16-bit hash of the parent's name.
/// At most 13 bytes, within IFNAMSIZ. Each name depends only on its own parent, so the same VLAN can be
/// used on redundant connections and adding a parent never renames existing links.
pub fn link_name(parent: &str, vlan: u16) -> String {
    let hash = crate::hash::fnv1a(parent.as_bytes());
    format!("rddx{:04x}.{vlan}", (hash >> 16) ^ (hash & 0xffff))
}

fn ignore(resource: &str, reason: impl Into<String>) -> Ignored {
    Ignored { resource: resource.to_string(), reason: reason.into() }
}

fn asn(value: Option<i64>) -> Option<u32> {
    value.and_then(|v| u32::try_from(v).ok()).filter(|v| *v != 0)
}

/// `local` holds addresses configured on this router; `ports` maps connection/LAG IDs to parent interfaces.
pub fn resolve(vifs: &[Vif], local: &[IpAddr], ports: &BTreeMap<String, String>) -> Discovered {
    let mut found = Discovered::default();
    // Each link name backs one VIF; the first keeps it (same parent and VLAN, or a parent-hash collision).
    let mut claimed: BTreeMap<String, &str> = BTreeMap::new();
    for vif in vifs {
        let parent = ports.get(&vif.connection_id);
        let configured = vif.peers.iter().any(|p| p.customer_address.parse::<IpNet>().is_ok_and(|n| local.contains(&n.addr())));
        if parent.is_none() && !configured {
            continue;
        }
        if vif.kind == "public" {
            found.ignored.push(ignore(
                &vif.id,
                "public VIFs are not supported: they carry AWS public prefixes and need owned public space",
            ));
            continue;
        }
        if !matches!(vif.state.as_str(), "available" | "down") {
            found.ignored.push(ignore(&vif.id, format!("state {}", vif.state)));
            continue;
        }
        let Some(remote_asn) = asn(vif.amazon_side_asn) else {
            found.ignored.push(ignore(&vif.id, "missing Amazon-side ASN"));
            continue;
        };
        if !(1..=4094).contains(&vif.vlan) {
            found.ignored.push(ignore(&vif.id, format!("invalid VLAN {}", vif.vlan)));
            continue;
        }
        let interface = parent.map(|parent| link_name(parent, vif.vlan));
        if let (Some(parent), Some(name)) = (parent, &interface) {
            if let Some(first) = claimed.get(name) {
                found.ignored.push(ignore(&vif.id, format!("VLAN {} on {parent} ({name}) already used by {first}", vif.vlan)));
                continue;
            }
            claimed.insert(name.clone(), &vif.id);
        }
        let mut addresses = vec![];
        for peer in &vif.peers {
            if matches!(peer.state.as_str(), "deleting" | "deleted") {
                continue;
            }
            let (Ok(amazon), Ok(customer), Some(local_asn)) =
                (peer.amazon_address.parse::<IpNet>(), peer.customer_address.parse::<IpNet>(), asn(peer.asn))
            else {
                found.ignored.push(ignore(&peer.id, "incomplete BGP peer addressing or ASN"));
                continue;
            };
            addresses.push(customer);
            found.neighbors.push(Neighbor {
                vif: vif.id.clone(),
                kind: vif.kind.clone(),
                address: amazon.addr(),
                local: customer,
                remote_asn,
                local_asn,
                password: peer.auth_key.clone().filter(|k| !k.is_empty()),
                interface: interface.clone(),
            });
        }
        if let (Some(parent), Some(name)) = (parent, interface) {
            if !addresses.is_empty() {
                found.links.push(VlanLink { name, parent: parent.clone(), vlan: vif.vlan, mtu: vif.mtu, addresses });
            }
        }
    }
    found.neighbors.sort_by(|a, b| (&a.vif, a.address).cmp(&(&b.vif, b.address)));
    found
}

#[cfg(feature = "aws")]
pub use sdk::SdkDirectConnect;

#[cfg(feature = "aws")]
mod sdk {
    use std::time::Duration;

    use aws_config::retry::RetryConfig;
    use aws_config::timeout::TimeoutConfig;
    use aws_config::{BehaviorVersion, Region};
    use aws_sdk_directconnect::error::DisplayErrorContext;
    use aws_sdk_directconnect::Client;

    use super::*;
    use crate::error::Error;

    /// One client per region; VIFs are regional resources.
    pub struct SdkDirectConnect {
        clients: Vec<(String, Client)>,
    }

    impl SdkDirectConnect {
        /// Empty `regions` uses the region from the standard AWS configuration chain.
        pub async fn new(regions: &[String]) -> Result<Self> {
            let timeouts =
                TimeoutConfig::builder().connect_timeout(Duration::from_secs(3)).read_timeout(Duration::from_secs(10)).build();
            let load = |region: Option<String>| {
                let mut loader = aws_config::defaults(BehaviorVersion::latest())
                    .timeout_config(timeouts.clone())
                    .retry_config(RetryConfig::standard().with_max_attempts(3));
                if let Some(region) = region {
                    loader = loader.region(Region::new(region));
                }
                loader.load()
            };
            let mut clients = vec![];
            if regions.is_empty() {
                let config = load(None).await;
                let Some(region) = config.region().map(|r| r.to_string()) else {
                    return crate::error::config_err("no AWS region: pass --region or set AWS_REGION");
                };
                clients.push((region, Client::new(&config)));
            } else {
                for region in regions {
                    clients.push((region.clone(), Client::new(&load(Some(region.clone())).await)));
                }
            }
            Ok(SdkDirectConnect { clients })
        }
    }

    fn api<E: std::error::Error + 'static>(e: E) -> Error {
        Error::Backend(format!("Direct Connect: {}", DisplayErrorContext(e)))
    }

    fn text(value: Option<&str>) -> String {
        value.unwrap_or_default().to_string()
    }

    #[async_trait]
    impl DirectConnect for SdkDirectConnect {
        async fn virtual_interfaces(&self) -> Result<Vec<Vif>> {
            let mut vifs = vec![];
            for (region, client) in &self.clients {
                let mut token: Option<String> = None;
                loop {
                    let output = client.describe_virtual_interfaces().set_next_token(token.clone()).send().await.map_err(api)?;
                    for v in output.virtual_interfaces() {
                        vifs.push(Vif {
                            id: text(v.virtual_interface_id()),
                            region: v.region().map_or_else(|| region.clone(), str::to_string),
                            connection_id: text(v.connection_id()),
                            kind: text(v.virtual_interface_type()),
                            state: v.virtual_interface_state().map(|s| s.as_str().to_string()).unwrap_or_default(),
                            vlan: u16::try_from(v.vlan()).unwrap_or(0),
                            amazon_side_asn: v.amazon_side_asn(),
                            mtu: v.mtu().and_then(|m| u32::try_from(m).ok()),
                            peers: v
                                .bgp_peers()
                                .iter()
                                .map(|p| BgpPeer {
                                    id: text(p.bgp_peer_id()),
                                    asn: p.asn_long().or(Some(i64::from(p.asn()))),
                                    auth_key: p.auth_key().map(str::to_string),
                                    amazon_address: text(p.amazon_address()),
                                    customer_address: text(p.customer_address()),
                                    state: p.bgp_peer_state().map(|s| s.as_str().to_string()).unwrap_or_default(),
                                })
                                .collect(),
                        });
                    }
                    token = output.next_token().map(str::to_string);
                    if token.is_none() {
                        break;
                    }
                }
            }
            Ok(vifs)
        }
    }
}
