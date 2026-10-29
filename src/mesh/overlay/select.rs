//! Which hosts relay for each site, and which peers this host tunnels to. Every host computes the
//! same answer from the same registry view, so no coordination is needed.
//!
//! - Each site's relays are its `relays` most senior live hosts (oldest `since`, then host ID).
//! - A relay tunnels to every relay of every other site, and to every other live host of its own site.
//! - Any other host tunnels to its own site's relays only.

use std::collections::BTreeMap;

use serde::Serialize;

use super::registry::Entry;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Selection {
    pub relay: bool,
    /// Relays per site, as host IDs.
    pub relays: BTreeMap<String, Vec<String>>,
    pub peers: Vec<Entry>,
    /// Entries ignored, with the reason.
    pub stale: Vec<String>,
}

/// `entries` holds every registered host with its heartbeat age in seconds, including this one.
pub fn select(own: &Entry, entries: &[(Entry, i64)], ttl: i64, relays: usize) -> Selection {
    let mut selection = Selection::default();
    let mut sites: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
    for (entry, age) in entries {
        if entry.host != own.host && *age > ttl {
            selection.stale.push(format!("{} ({}): no heartbeat for {age} s", entry.host, entry.name));
            continue;
        }
        if entry.host != own.host && entry.endpoint == own.endpoint {
            selection.stale.push(format!("{} ({}): same endpoint {} as this host", entry.host, entry.name, entry.endpoint));
            continue;
        }
        sites.entry(entry.site.as_str()).or_default().push(entry);
    }
    for members in sites.values_mut() {
        members.sort_by(|a, b| (a.since, &a.host).cmp(&(b.since, &b.host)));
        members.dedup_by(|a, b| a.host == b.host);
    }
    let chosen: BTreeMap<&str, Vec<&Entry>> =
        sites.iter().map(|(site, members)| (*site, members.iter().take(relays.max(1)).copied().collect())).collect();
    selection.relays = chosen.iter().map(|(site, r)| (site.to_string(), r.iter().map(|e| e.host.clone()).collect())).collect();
    let own_relays = chosen.get(own.site.as_str()).cloned().unwrap_or_default();
    selection.relay = own_relays.iter().any(|e| e.host == own.host);
    let mut peers: Vec<&Entry> = if selection.relay {
        let mut peers: Vec<&Entry> =
            chosen.iter().filter(|(site, _)| **site != own.site).flat_map(|(_, r)| r.iter().copied()).collect();
        peers.extend(sites.get(own.site.as_str()).into_iter().flatten().copied());
        peers
    } else {
        own_relays
    };
    peers.retain(|e| e.host != own.host);
    peers.sort_by(|a, b| a.host.cmp(&b.host));
    peers.dedup_by(|a, b| a.host == b.host);
    selection.peers = peers.into_iter().cloned().collect();
    selection.stale.sort();
    selection
}
