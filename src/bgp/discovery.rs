//! Find the AWS BGP peering points that name this instance: VPC Route Server peers and
//! Transit Gateway Connect peers whose peer address is one of this instance's ENI addresses.

use std::collections::BTreeMap;
use std::net::IpAddr;

use async_trait::async_trait;
use ipnet::IpNet;
use serde::Serialize;

use super::metadata::Host;
use super::registration::PeerRequest;
use crate::error::Result;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteServerPeer {
    pub id: String,
    pub route_server_id: String,
    pub vpc_id: String,
    pub state: String,
    pub endpoint_address: String,
    pub peer_address: String,
    pub peer_asn: Option<i64>,
    /// `bfd` or `bgp-keepalive`
    pub liveness: Option<String>,
    pub endpoint_id: String,
    /// Value of the registration owner tag, when this mode created the peer.
    pub owner: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteServerEndpoint {
    pub id: String,
    pub route_server_id: String,
    pub vpc_id: String,
    pub subnet_id: String,
    pub state: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectBgp {
    pub transit_gateway_asn: Option<i64>,
    pub peer_asn: Option<i64>,
    pub transit_gateway_address: String,
    pub peer_address: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectPeer {
    pub id: String,
    pub state: String,
    /// GRE outer addresses.
    pub transit_gateway_address: String,
    pub peer_address: String,
    pub inside_cidrs: Vec<String>,
    pub protocol: String,
    pub bgp: Vec<ConnectBgp>,
}

#[async_trait]
pub trait Peering: Send + Sync {
    async fn route_server_peers(&self) -> Result<Vec<RouteServerPeer>>;
    /// Amazon-side ASN by route server ID.
    async fn route_server_asns(&self, ids: &[String]) -> Result<BTreeMap<String, i64>>;
    async fn connect_peers(&self) -> Result<Vec<ConnectPeer>>;
    /// Source/destination check by ENI ID.
    async fn source_dest_checks(&self, eni_ids: &[String]) -> Result<BTreeMap<String, bool>>;
    async fn route_server_endpoints(&self) -> Result<Vec<RouteServerEndpoint>>;
    /// Returns the new peer's ID.
    async fn create_route_server_peer(&self, request: &PeerRequest) -> Result<String>;
    async fn delete_route_server_peer(&self, id: &str) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    RouteServer,
    TgwConnect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Gre {
    pub name: String,
    pub local: IpAddr,
    pub remote: IpAddr,
    /// This end's inside address with the Connect inside CIDR length.
    pub inside: Vec<IpNet>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Neighbor {
    pub kind: Kind,
    /// AWS resource that defines this session.
    pub resource: String,
    pub address: IpAddr,
    pub local_address: IpAddr,
    pub remote_asn: u32,
    pub local_asn: u32,
    pub bfd: bool,
    pub multihop: Option<u8>,
    /// ENI whose source/destination check gates advertisement to this neighbor; None through GRE.
    pub eni: Option<String>,
    pub tunnel: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Ignored {
    pub resource: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Discovered {
    pub neighbors: Vec<Neighbor>,
    pub tunnels: Vec<Gre>,
    pub ignored: Vec<Ignored>,
}

fn asn(value: Option<i64>) -> Option<u32> {
    value.and_then(|v| u32::try_from(v).ok()).filter(|v| *v != 0)
}

fn ignore(resource: &str, reason: impl Into<String>) -> Ignored {
    Ignored { resource: resource.to_string(), reason: reason.into() }
}

/// Interface name from the Connect peer ID; IFNAMSIZ allows 15 characters.
pub fn tunnel_name(peer_id: &str) -> String {
    let id = peer_id.trim_start_matches("tgw-connect-peer-");
    format!("rdgre{}", &id[id.len().saturating_sub(9)..])
}

pub fn resolve(
    host: &Host,
    route_servers: &[RouteServerPeer],
    asns: &BTreeMap<String, i64>,
    connects: &[ConnectPeer],
) -> Discovered {
    let mine = |text: &str| text.parse::<IpAddr>().ok().filter(|a| host.addresses().any(|m| m == *a));
    let mut found = Discovered::default();
    for peer in route_servers {
        let Some(local) = mine(&peer.peer_address) else { continue };
        if peer.vpc_id != host.vpc_id {
            found.ignored.push(ignore(&peer.id, "route server peer is in another VPC"));
            continue;
        }
        if peer.state != "available" {
            found.ignored.push(ignore(&peer.id, format!("state {}", peer.state)));
            continue;
        }
        let (Ok(address), Some(local_asn), Some(remote_asn)) =
            (peer.endpoint_address.parse::<IpAddr>(), asn(peer.peer_asn), asn(asns.get(&peer.route_server_id).copied()))
        else {
            found.ignored.push(ignore(&peer.id, "missing endpoint address or ASN"));
            continue;
        };
        found.neighbors.push(Neighbor {
            kind: Kind::RouteServer,
            resource: peer.id.clone(),
            address,
            local_address: local,
            remote_asn,
            local_asn,
            bfd: peer.liveness.as_deref() == Some("bfd"),
            multihop: None,
            eni: host.eni_of(local).map(|e| e.id.clone()),
            tunnel: None,
        });
    }
    for peer in connects {
        let Some(local) = mine(&peer.peer_address) else { continue };
        if peer.state != "available" {
            found.ignored.push(ignore(&peer.id, format!("state {}", peer.state)));
            continue;
        }
        if peer.protocol != "gre" {
            found.ignored.push(ignore(&peer.id, format!("unsupported Connect protocol {}", peer.protocol)));
            continue;
        }
        let Ok(remote) = peer.transit_gateway_address.parse::<IpAddr>() else {
            found.ignored.push(ignore(&peer.id, "invalid transit gateway GRE address"));
            continue;
        };
        let cidrs: Vec<IpNet> = peer.inside_cidrs.iter().filter_map(|c| c.parse().ok()).collect();
        let name = tunnel_name(&peer.id);
        let mut inside = vec![];
        for bgp in &peer.bgp {
            let (Ok(address), Ok(local_inside), Some(local_asn), Some(remote_asn)) = (
                bgp.transit_gateway_address.parse::<IpAddr>(),
                bgp.peer_address.parse::<IpAddr>(),
                asn(bgp.peer_asn),
                asn(bgp.transit_gateway_asn),
            ) else {
                found.ignored.push(ignore(&peer.id, "incomplete BGP configuration"));
                continue;
            };
            let Some(cidr) = cidrs.iter().find(|c| c.contains(&local_inside) && c.contains(&address)) else {
                found.ignored.push(ignore(&peer.id, format!("{local_inside} is outside the inside CIDRs")));
                continue;
            };
            let net = IpNet::new(local_inside, cidr.prefix_len()).unwrap();
            if !inside.contains(&net) {
                inside.push(net);
            }
            // AWS's Connect peer examples use eBGP multihop 2 for both TGW inside addresses.
            found.neighbors.push(Neighbor {
                kind: Kind::TgwConnect,
                resource: peer.id.clone(),
                address,
                local_address: local_inside,
                remote_asn,
                local_asn,
                bfd: false,
                multihop: Some(2),
                eni: None,
                tunnel: Some(name.clone()),
            });
        }
        if !inside.is_empty() {
            found.tunnels.push(Gre { name, local, remote, inside });
        }
    }
    found.neighbors.sort_by(|a, b| (&a.kind, a.address).cmp(&(&b.kind, b.address)));
    found.neighbors.dedup_by(|a, b| a.address == b.address);
    found
}

#[cfg(feature = "aws")]
pub use sdk::SdkPeering;

#[cfg(feature = "aws")]
mod sdk {
    use std::time::Duration;

    use aws_config::retry::RetryConfig;
    use aws_config::timeout::TimeoutConfig;
    use aws_config::{BehaviorVersion, Region};
    use aws_sdk_ec2::error::DisplayErrorContext;
    use aws_sdk_ec2::Client;

    use super::*;
    use crate::bgp::registration::OWNER_TAG;
    use crate::error::Error;

    pub struct SdkPeering {
        client: Client,
    }

    impl SdkPeering {
        pub async fn new(region: &str) -> Self {
            let timeouts =
                TimeoutConfig::builder().connect_timeout(Duration::from_secs(2)).read_timeout(Duration::from_secs(5)).build();
            let config = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region.to_string()))
                .timeout_config(timeouts)
                .retry_config(RetryConfig::standard().with_max_attempts(3))
                .load()
                .await;
            SdkPeering { client: Client::new(&config) }
        }
    }

    fn api<E: std::error::Error + 'static>(e: E) -> Error {
        Error::Backend(format!("EC2: {}", DisplayErrorContext(e)))
    }

    fn text(value: Option<&str>) -> String {
        value.unwrap_or_default().to_string()
    }

    #[async_trait]
    impl Peering for SdkPeering {
        async fn route_server_peers(&self) -> Result<Vec<RouteServerPeer>> {
            let mut pages = self.client.describe_route_server_peers().into_paginator().items().send();
            let mut peers = vec![];
            while let Some(peer) = pages.next().await {
                let peer = peer.map_err(api)?;
                let options = peer.bgp_options();
                peers.push(RouteServerPeer {
                    id: text(peer.route_server_peer_id()),
                    route_server_id: text(peer.route_server_id()),
                    vpc_id: text(peer.vpc_id()),
                    state: peer.state().map(|s| s.as_str().to_string()).unwrap_or_default(),
                    endpoint_address: text(peer.endpoint_eni_address()),
                    peer_address: text(peer.peer_address()),
                    peer_asn: options.and_then(|o| o.peer_asn()),
                    liveness: options.and_then(|o| o.peer_liveness_detection()).map(|l| l.as_str().to_string()),
                    endpoint_id: text(peer.route_server_endpoint_id()),
                    owner: peer.tags().iter().find(|t| t.key() == Some(OWNER_TAG)).and_then(|t| t.value()).map(str::to_string),
                });
            }
            Ok(peers)
        }

        async fn route_server_asns(&self, ids: &[String]) -> Result<BTreeMap<String, i64>> {
            if ids.is_empty() {
                return Ok(BTreeMap::new());
            }
            let output =
                self.client.describe_route_servers().set_route_server_ids(Some(ids.to_vec())).send().await.map_err(api)?;
            Ok(output
                .route_servers()
                .iter()
                .filter_map(|s| Some((s.route_server_id()?.to_string(), s.amazon_side_asn()?)))
                .collect())
        }

        async fn connect_peers(&self) -> Result<Vec<ConnectPeer>> {
            let mut pages = self.client.describe_transit_gateway_connect_peers().into_paginator().items().send();
            let mut peers = vec![];
            while let Some(peer) = pages.next().await {
                let peer = peer.map_err(api)?;
                let Some(config) = peer.connect_peer_configuration() else { continue };
                peers.push(ConnectPeer {
                    id: text(peer.transit_gateway_connect_peer_id()),
                    state: peer.state().map(|s| s.as_str().to_string()).unwrap_or_default(),
                    transit_gateway_address: text(config.transit_gateway_address()),
                    peer_address: text(config.peer_address()),
                    inside_cidrs: config.inside_cidr_blocks().to_vec(),
                    protocol: config.protocol().map(|p| p.as_str().to_string()).unwrap_or_default(),
                    bgp: config
                        .bgp_configurations()
                        .iter()
                        .map(|b| ConnectBgp {
                            transit_gateway_asn: b.transit_gateway_asn(),
                            peer_asn: b.peer_asn(),
                            transit_gateway_address: text(b.transit_gateway_address()),
                            peer_address: text(b.peer_address()),
                        })
                        .collect(),
                });
            }
            Ok(peers)
        }

        async fn source_dest_checks(&self, eni_ids: &[String]) -> Result<BTreeMap<String, bool>> {
            if eni_ids.is_empty() {
                return Ok(BTreeMap::new());
            }
            let output = self
                .client
                .describe_network_interfaces()
                .set_network_interface_ids(Some(eni_ids.to_vec()))
                .send()
                .await
                .map_err(api)?;
            Ok(output
                .network_interfaces()
                .iter()
                .filter_map(|e| Some((e.network_interface_id()?.to_string(), e.source_dest_check().unwrap_or(true))))
                .collect())
        }

        async fn route_server_endpoints(&self) -> Result<Vec<RouteServerEndpoint>> {
            let mut pages = self.client.describe_route_server_endpoints().into_paginator().items().send();
            let mut endpoints = vec![];
            while let Some(endpoint) = pages.next().await {
                let endpoint = endpoint.map_err(api)?;
                endpoints.push(RouteServerEndpoint {
                    id: text(endpoint.route_server_endpoint_id()),
                    route_server_id: text(endpoint.route_server_id()),
                    vpc_id: text(endpoint.vpc_id()),
                    subnet_id: text(endpoint.subnet_id()),
                    state: endpoint.state().map(|s| s.as_str().to_string()).unwrap_or_default(),
                });
            }
            Ok(endpoints)
        }

        async fn create_route_server_peer(&self, request: &PeerRequest) -> Result<String> {
            use aws_sdk_ec2::types::{
                ResourceType, RouteServerBgpOptionsRequest, RouteServerPeerLivenessMode, Tag, TagSpecification,
            };
            let options = RouteServerBgpOptionsRequest::builder()
                .peer_asn(i64::from(request.peer_asn))
                .peer_liveness_detection(RouteServerPeerLivenessMode::from(request.liveness.as_str()))
                .build();
            let tags = TagSpecification::builder()
                .resource_type(ResourceType::RouteServerPeer)
                .tags(Tag::builder().key(OWNER_TAG).value(&request.owner).build())
                .build();
            let output = self
                .client
                .create_route_server_peer()
                .route_server_endpoint_id(&request.endpoint_id)
                .peer_address(&request.peer_address)
                .bgp_options(options)
                .tag_specifications(tags)
                .send()
                .await
                .map_err(api)?;
            Ok(text(output.route_server_peer().and_then(|p| p.route_server_peer_id())))
        }

        async fn delete_route_server_peer(&self, id: &str) -> Result<()> {
            self.client.delete_route_server_peer().route_server_peer_id(id).send().await.map_err(api)?;
            Ok(())
        }
    }
}
