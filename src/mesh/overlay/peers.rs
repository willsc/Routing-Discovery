//! Static peer list: the alternative to the S3 registry, for hosts that should hold no AWS credentials.
//!
//! The same JSON file goes to every host, through whatever already manages them:
//!
//! ```json
//! [
//!   {"host": "a1", "endpoint": "10.1.0.11", "site": "vpc-a"},
//!   {"host": "a2", "endpoint": "10.1.0.12", "site": "vpc-a"},
//!   {"host": "m1", "endpoint": "192.168.50.5"}
//! ]
//! ```
//!
//! A host finds itself by its endpoint and takes its ID and site from its entry, so IDs are free-form
//! names. File order is seniority: each site's first hosts relay. There is no heartbeat, so every
//! listed host counts as live; Babel routes around the ones that aren't.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use serde::Deserialize;

use super::registry::{Entry, Platform};
use crate::error::{Error, Result};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    host: String,
    endpoint: Ipv4Addr,
    /// Defaults to the host itself: a site of one, like a bare-metal host.
    site: Option<String>,
    name: Option<String>,
}

/// Entries in file order, with `since` set to each entry's position.
pub fn parse(text: &str) -> Result<Vec<Entry>> {
    let peers: Vec<Peer> = serde_json::from_str(text).map_err(|e| Error::Config(format!("peers file: {e}")))?;
    let (mut hosts, mut endpoints) = (BTreeSet::new(), BTreeSet::new());
    let mut entries = vec![];
    for (index, peer) in peers.into_iter().enumerate() {
        if peer.host.is_empty() || peer.host.contains('/') {
            return Err(Error::Config(format!("peers file: entry {}: invalid host {:?}", index + 1, peer.host)));
        }
        if !hosts.insert(peer.host.clone()) {
            return Err(Error::Config(format!("peers file: host {} is listed twice", peer.host)));
        }
        if !endpoints.insert(peer.endpoint) {
            return Err(Error::Config(format!("peers file: endpoint {} is listed twice", peer.endpoint)));
        }
        entries.push(Entry {
            site: peer.site.unwrap_or_else(|| peer.host.clone()),
            name: peer.name.unwrap_or_else(|| peer.host.clone()),
            host: peer.host,
            platform: Platform::Metal,
            endpoint: peer.endpoint,
            since: index as i64,
        });
    }
    Ok(entries)
}

/// This host as the file lists it, keeping its discovered platform, and every entry aged 0.
pub fn resolve(discovered: &Entry, entries: Vec<Entry>) -> Result<(Entry, Vec<(Entry, i64)>)> {
    let own = entries.iter().find(|e| e.endpoint == discovered.endpoint).cloned().ok_or_else(|| {
        Error::Config(format!(
            "peers file: this host's endpoint {} is not listed; pass --endpoint if it differs",
            discovered.endpoint
        ))
    })?;
    let own = Entry { platform: discovered.platform, ..own };
    let entries = entries.into_iter().map(|e| if e.host == own.host { own.clone() } else { e }).map(|e| (e, 0)).collect();
    Ok((own, entries))
}
