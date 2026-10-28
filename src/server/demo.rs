use std::sync::{Arc, Mutex};

use super::config::{Endpoint, Peer, Propagation, ServerConfig};
use super::journal::Journal;
use super::propagation::Propagator;
use super::rib::{LearnedRoute, PeerState, Rib, Snapshot};
use crate::error::{backend_err, Result};

pub fn demo_config() -> ServerConfig {
    let peer = |id: &str, address: &str, asn: u32, eni: &str| Peer {
        id: id.into(),
        endpoint: "edge".into(),
        address: address.parse().unwrap(),
        asn,
        eni: eni.into(),
        next_hops: vec![address.into()],
        allowed_prefixes: vec!["10.20.0.0/16".into()],
        max_prefixes: 100,
        local_pref: 100,
        bfd: true,
    };
    ServerConfig {
        id: "demo".into(),
        asn: 64512,
        region: "eu-west-2".into(),
        vpc_id: "vpc-0123456789abcdef0".into(),
        endpoints: vec![Endpoint {
            id: "edge".into(),
            address: "10.0.1.5".parse().unwrap(),
            router_id: "10.0.1.5".parse().unwrap(),
            socket_dir: "/run/frr".into(),
        }],
        peers: vec![
            peer("primary", "10.0.1.10", 65010, "eni-0123456789abcdef0"),
            peer("backup", "10.0.1.20", 65020, "eni-0fedcba9876543210"),
        ],
        propagations: vec![Propagation::new("rtb-0123456789abcdef0"), Propagation::new("rtb-0fedcba9876543210")],
        state_dir: "/var/lib/route-discovery-server".into(),
        listen: "127.0.0.1".parse().unwrap(),
        port: 9809,
        poll_interval: 1.0,
        reconcile_interval: 5.0,
        stale_after: 10.0,
        failback_delay: 5.0,
        persist_routes: false,
        persist_duration: 60.0,
        owner_tag: "route-discovery-server".into(),
    }
}

pub async fn demo() -> Result<()> {
    let config = demo_config();
    let journal = Arc::new(Mutex::new(Journal::open(&config, None)?));
    let mut rib = Rib::new(config.clone());
    let backend = Propagator::new(config.clone(), journal, None, false)?;
    let routes: Vec<LearnedRoute> = config
        .peers
        .iter()
        .zip([10, 100])
        .map(|(p, med)| LearnedRoute {
            prefix: "10.20.1.0/24".into(),
            peer: p.id.clone(),
            endpoint: p.endpoint.clone(),
            eni: p.eni.clone(),
            next_hop: p.next_hops[0].clone(),
            as_path: vec![p.asn],
            med,
            local_pref: 100,
        })
        .collect();
    let (primary, backup) = (&routes[0], &routes[1]);
    let steps: [(u32, Vec<&LearnedRoute>, &str); 5] = [
        (0, vec![primary, backup], "BGP learns two paths"),
        (1, vec![backup], "Primary BFD session fails"),
        (2, vec![primary, backup], "Primary returns; hold-down"),
        (7, vec![primary, backup], "Stable recovery; failback"),
        (8, vec![], "Both peers withdraw prefix"),
    ];
    for (tick, available, title) in steps {
        let peers =
            config.peers.iter().map(|p| (p.id.clone(), PeerState::up(available.iter().any(|r| r.peer == p.id)))).collect();
        let snapshot = Snapshot { routes: available.into_iter().cloned().collect(), peers, rejected: vec![] };
        rib.update("edge", snapshot, f64::from(tick));
        let fib = rib.select(f64::from(tick));
        if !backend.reconcile(&fib, &|| true).await? {
            return backend_err("simulated propagation did not converge");
        }
        let winners: Vec<&str> = fib.values().map(|r| r.peer.as_str()).collect();
        let winners = if winners.is_empty() { "withdrawn".to_string() } else { winners.join(", ") };
        println!("t={tick:2}s {title}: {winners}; {} tables converged", backend.status.lock().unwrap().len());
    }
    Ok(())
}
