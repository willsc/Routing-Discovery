//! Self-registration: create a VPC Route Server peer for this instance on every available
//! route server endpoint in one of its ENI subnets. Peers it creates carry the owner tag with
//! this instance's ID, and only those are ever deleted.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::Serialize;

use super::discovery::{Ignored, RouteServerEndpoint, RouteServerPeer};
use super::metadata::Host;

pub const OWNER_TAG: &str = "route-discovery:owner";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub asn: u32,
    /// `bfd` or `bgp-keepalive`
    pub liveness: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PeerRequest {
    pub endpoint_id: String,
    pub peer_address: String,
    pub peer_asn: u32,
    pub liveness: String,
    pub owner: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Changes {
    pub create: Vec<PeerRequest>,
    /// Owned peer IDs that no longer match an endpoint/address pair, or failed.
    pub delete: Vec<String>,
    pub ignored: Vec<Ignored>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.create.is_empty() && self.delete.is_empty()
    }
}

fn gone(state: &str) -> bool {
    matches!(state, "deleting" | "deleted")
}

/// Route server endpoints are peered from their own subnet, so each endpoint pairs with the
/// primary IPv4 address of this instance's ENI in that subnet.
pub fn plan(
    host: &Host,
    endpoints: &[RouteServerEndpoint],
    peers: &[RouteServerPeer],
    asns: &BTreeMap<String, i64>,
    registration: &Registration,
) -> Changes {
    let mut changes = Changes::default();
    let mut wanted: BTreeSet<(String, String)> = BTreeSet::new();
    for endpoint in endpoints.iter().filter(|e| e.vpc_id == host.vpc_id) {
        let Some(address) = host
            .enis
            .iter()
            .find(|eni| eni.subnet_id == endpoint.subnet_id)
            .and_then(|eni| eni.addresses.iter().find(|a| a.is_ipv4()))
            .map(IpAddr::to_string)
        else {
            continue;
        };
        if endpoint.state != "available" {
            changes.ignored.push(Ignored { resource: endpoint.id.clone(), reason: format!("endpoint state {}", endpoint.state) });
            continue;
        }
        if asns.get(&endpoint.route_server_id).is_some_and(|asn| *asn == i64::from(registration.asn)) {
            changes.ignored.push(Ignored {
                resource: endpoint.id.clone(),
                reason: format!("registration ASN {} equals the route server's ASN; eBGP needs distinct ASNs", registration.asn),
            });
            continue;
        }
        wanted.insert((endpoint.id.clone(), address.clone()));
        // A failed peer blocks re-creation until its deletion completes.
        let existing = peers.iter().any(|p| p.endpoint_id == endpoint.id && p.peer_address == address && !gone(&p.state));
        if !existing {
            changes.create.push(PeerRequest {
                endpoint_id: endpoint.id.clone(),
                peer_address: address,
                peer_asn: registration.asn,
                liveness: registration.liveness.clone(),
                owner: host.instance_id.clone(),
            });
        }
    }
    for peer in peers.iter().filter(|p| p.owner.as_deref() == Some(host.instance_id.as_str()) && !gone(&p.state)) {
        let current = wanted.contains(&(peer.endpoint_id.clone(), peer.peer_address.clone()));
        if !current || peer.state == "failed" {
            changes.delete.push(peer.id.clone());
        }
    }
    changes
}

/// Every peer this instance owns, for withdrawal.
pub fn owned(host: &Host, peers: &[RouteServerPeer]) -> Vec<String> {
    peers
        .iter()
        .filter(|p| p.owner.as_deref() == Some(host.instance_id.as_str()) && !gone(&p.state))
        .map(|p| p.id.clone())
        .collect()
}
