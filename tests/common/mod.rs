#![allow(dead_code)]

use std::path::PathBuf;

use route_discovery::config::{Backend, BackendKind, Candidate, Config, Health, Probe, Route};
use route_discovery::server::config::ServerConfig;
use route_discovery::server::demo::demo_config;
use serde_json::{json, Value};

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn probe(host: &str, port: u16, device: &str, mark: u32) -> Probe {
    Probe { device: Some(device.into()), mark: Some(mark), ..Probe::new(host, port) }
}

pub fn configuration(kind: BackendKind, health: impl FnOnce(&mut Health)) -> Config {
    let mut primary = Candidate::new("primary", vec![probe("10.20.0.10", 443, "wg-a", 10101)]);
    primary.device = Some("wg-a".into());
    primary.aws_target = Some("eni-0123456789abcdef0".into());
    primary.local_pref = 200;
    let mut backup = Candidate::new("backup", vec![probe("10.20.0.10", 443, "wg-b", 10102)]);
    backup.device = Some("wg-b".into());
    backup.aws_target = Some("eni-0fedcba9876543210".into());
    let mut config = Config::new(vec![Route::new("10.20.0.0/16", vec![primary, backup])]);
    health(&mut config.health);
    config.backend = Backend {
        kind,
        region: Some("eu-west-2".into()),
        route_table_id: Some("rtb-0123456789abcdef0".into()),
        ..Backend::default()
    };
    config
}

pub fn linux() -> Config {
    configuration(BackendKind::Linux, |_| {})
}

/// FRR JSON for two established, BFD-up peers that both advertise 10.20.1.0/24.
pub fn source_data(config: &ServerConfig) -> Value {
    let peers: serde_json::Map<String, Value> =
        config.peers.iter().map(|p| (p.address.to_string(), json!({"state": "Established", "remoteAs": p.asn}))).collect();
    let bfd: Vec<Value> = config
        .peers
        .iter()
        .map(|p| json!({"peer": p.address.to_string(), "local": config.endpoints[0].address.to_string(), "status": "up"}))
        .collect();
    let paths: Vec<Value> = config
        .peers
        .iter()
        .zip([10, 100])
        .map(|(p, med)| {
            json!({"peerId": p.address.to_string(), "valid": true, "path": p.asn.to_string(), "metric": med,
                   "nexthops": [{"ip": p.next_hops[0]}]})
        })
        .collect();
    json!({
        "summary": {"ipv4Unicast": {"peers": peers}},
        "bfd": bfd,
        "ipv4": {"routes": {"10.20.1.0/24": paths}},
    })
}

pub fn demo() -> ServerConfig {
    demo_config()
}
