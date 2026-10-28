mod common;

use std::sync::{Arc, Mutex};

use common::{demo, root, source_data};
use route_discovery::config::read_toml;
use route_discovery::error::Error;
use route_discovery::server::config::{parse, ServerConfig};
use route_discovery::server::frr::{parse_snapshot, render};
use route_discovery::server::journal::Journal;
use route_discovery::server::rib::{PeerState, Rib, Snapshot};
use serde_json::{json, Value};
use toml::Table;

fn raw() -> Table {
    read_toml(&root().join("examples/route-server.toml")).unwrap()
}

fn snapshot(config: &ServerConfig, data: &Value) -> Snapshot {
    parse_snapshot(config, &config.endpoints[0], data).unwrap()
}

#[test]
fn example_and_endpoint_config() {
    let text = render(&parse(&raw()).unwrap(), "endpoint-a").unwrap();
    for fragment in ["bgp no-rib", "maximum-prefix 100", "RDS-DENY-OUT out", "neighbor 10.0.1.10 bfd"] {
        assert!(text.contains(fragment), "{fragment}");
    }
    assert!(!text.contains("neighbor 10.0.2.10"));
}

#[test]
fn typo_duplicate_endpoint_and_unknown_peer_endpoint() {
    let edits: [fn(&mut Table); 5] = [
        |r| {
            r["server"].as_table_mut().unwrap().insert("poll_intervl".into(), 1.into());
        },
        |r| {
            let endpoints = r["endpoints"].as_array_mut().unwrap();
            endpoints.push(endpoints[0].clone());
        },
        |r| {
            r["peers"].as_array_mut().unwrap()[0].as_table_mut().unwrap().insert("endpoint".into(), "missing".into());
        },
        |r| {
            let asn = r["server"]["asn"].clone();
            r["peers"].as_array_mut().unwrap()[0].as_table_mut().unwrap().insert("asn".into(), asn);
        },
        |r| {
            r["propagations"].as_array_mut().unwrap()[0].as_table_mut().unwrap().insert("enabled".into(), "yes".into());
        },
    ];
    for edit in edits {
        let mut modified = raw();
        edit(&mut modified);
        assert!(matches!(parse(&modified), Err(Error::Config(_))));
    }
}

#[test]
fn learns_all_paths_not_just_frr_best() {
    let config = demo();
    let result = snapshot(&config, &source_data(&config));
    assert_eq!(result.routes.len(), 2);
    assert_eq!(result.routes[0].med, 10);
    assert_eq!(result.routes[1].as_path, [65020]);
}

#[test]
fn bfd_down_withdraws_only_failed_peer() {
    let config = demo();
    let mut data = source_data(&config);
    data["bfd"][0]["status"] = "down".into();
    let result = snapshot(&config, &data);
    assert_eq!(result.routes.iter().map(|r| r.peer.as_str()).collect::<Vec<_>>(), ["backup"]);
    assert!(!result.peers["primary"].up);
}

#[test]
fn wrong_asn_or_bgp_down_excludes_peer() {
    let config = demo();
    let mut data = source_data(&config);
    data["summary"]["ipv4Unicast"]["peers"]["10.0.1.10"]["remoteAs"] = 123.into();
    assert_eq!(snapshot(&config, &data).routes.len(), 1);
    data["summary"]["ipv4Unicast"]["peers"]["10.0.1.20"]["state"] = "Active".into();
    assert!(snapshot(&config, &data).routes.is_empty());
}

#[test]
fn stale_path_loop_bad_next_hop_and_as_set_are_rejected() {
    let config = demo();
    let base = source_data(&config);
    for (key, value) in [
        ("stale", json!(true)),
        ("valid", json!(false)),
        ("path", json!("65010 64512")),
        ("path", json!("65010 {65100,65200}")),
        ("nexthops", json!([{"ip": "10.99.99.99"}])),
        ("metric", json!(-1)),
    ] {
        let mut data = base.clone();
        data["ipv4"]["routes"]["10.20.1.0/24"][0][key] = value;
        let result = snapshot(&config, &data);
        assert_eq!(result.routes.len(), 1, "{key}");
        assert_eq!(result.rejected.len(), 1, "{key}");
    }
}

#[test]
fn prefix_filter_and_maximum_prefix() {
    let mut config = demo();
    let mut data = source_data(&config);
    data["ipv4"]["routes"]["0.0.0.0/0"] = data["ipv4"]["routes"]["10.20.1.0/24"].clone();
    assert_eq!(snapshot(&config, &data).routes.len(), 2);
    for peer in &mut config.peers {
        peer.max_prefixes = 1;
    }
    assert!(snapshot(&config, &data).routes.is_empty());
}

#[test]
fn malformed_snapshot_is_not_a_withdrawal() {
    let config = demo();
    let good = source_data(&config);
    let with = |key: &str, value: Value| {
        let mut data = good.clone();
        data[key] = value;
        data
    };
    for data in [
        json!({}),
        json!({"summary": {}}),
        with("ipv4", json!({"warning": "BGP unavailable"})),
        with("bfd", json!({})),
        with("ipv4", json!({"routes": []})),
    ] {
        assert!(parse_snapshot(&config, &config.endpoints[0], &data).is_err(), "{data}");
    }
}

#[test]
fn ipv6_nlri() {
    let mut config = demo();
    for (i, peer) in config.peers.iter_mut().enumerate() {
        peer.allowed_prefixes = vec!["2001:db8:20::/48".into()];
        peer.next_hops = vec![format!("2001:db8::{}", i + 1)];
    }
    let mut data = source_data(&config);
    let summary = data["summary"]["ipv4Unicast"].take();
    data["summary"] = json!({"ipv6Unicast": summary});
    let paths = data["ipv4"]["routes"]["10.20.1.0/24"].take();
    data.as_object_mut().unwrap().remove("ipv4");
    data["ipv6"] = json!({"routes": {"2001:db8:20:1::/64": paths}});
    assert_eq!(snapshot(&config, &data).routes.len(), 2);
}

fn rib_fixture(edit: impl FnOnce(&mut ServerConfig)) -> (ServerConfig, Rib, Snapshot) {
    let mut config = demo();
    edit(&mut config);
    let snapshot = snapshot(&config, &source_data(&config));
    (config.clone(), Rib::new(config), snapshot)
}

fn only_backup(snapshot: &Snapshot) -> Snapshot {
    Snapshot { routes: snapshot.routes[1..].to_vec(), ..snapshot.clone() }
}

#[test]
fn rib_failover_failback_and_withdrawal() {
    let (_, mut rib, snap) = rib_fixture(|_| {});
    let winner = |rib: &mut Rib, now: f64| rib.select(now)["10.20.1.0/24"].peer.clone();
    rib.update("edge", snap.clone(), 0.0);
    assert_eq!(winner(&mut rib, 0.0), "primary");
    rib.update("edge", only_backup(&snap), 1.0);
    assert_eq!(winner(&mut rib, 1.0), "backup");
    rib.update("edge", snap.clone(), 2.0);
    assert_eq!(winner(&mut rib, 2.0), "backup");
    assert_eq!(winner(&mut rib, 7.0), "primary");
    rib.update("edge", Snapshot { routes: vec![], ..snap }, 8.0);
    assert!(rib.select(8.0).is_empty());
}

#[test]
fn stale_source_expires_and_recovery_restarts_hold_down() {
    let (_, mut rib, snap) = rib_fixture(|_| {});
    rib.update("edge", snap.clone(), 0.0);
    rib.select(0.0);
    assert!(rib.select(11.0).is_empty());
    rib.update("edge", snap.clone(), 12.0);
    assert_eq!(rib.since[&snap.routes[0].key()], 12.0);
}

#[test]
fn rank_prefers_aspath_before_med() {
    let (_, mut rib, snap) = rib_fixture(|_| {});
    let mut routes = snap.routes.clone();
    routes[0].as_path = vec![65010, 65100];
    let prefix = routes[0].prefix.clone();
    rib.update("edge", Snapshot { routes, ..snap }, 0.0);
    assert_eq!(rib.select(0.0)[&prefix].peer, "backup");
}

#[test]
fn persistence_when_all_peers_down_and_resume_delay() {
    let (config, mut rib, snap) = rib_fixture(|c| (c.persist_routes, c.persist_duration) = (true, 60.0));
    rib.update("edge", snap.clone(), 0.0);
    let original = rib.select(0.0);
    let down =
        Snapshot { peers: config.peers.iter().map(|p| (p.id.clone(), PeerState::up(false))).collect(), ..Default::default() };
    rib.update("edge", down, 1.0);
    assert_eq!(rib.select(1.0), original);
    assert!(rib.persisted);
    rib.update("edge", only_backup(&snap), 2.0);
    assert_eq!(rib.select(2.0), original);
    let mut selected = Default::default();
    for tick in [10.0, 18.0, 26.0, 34.0, 42.0, 50.0, 58.0, 62.0] {
        rib.update("edge", only_backup(&snap), tick);
        selected = rib.select(tick);
    }
    assert_eq!(selected["10.20.1.0/24"].peer, "backup");
    assert!(!rib.persisted);
}

#[test]
fn one_remaining_peer_allows_normal_withdrawal_with_persistence() {
    let (_, mut rib, snap) = rib_fixture(|c| c.persist_routes = true);
    rib.update("edge", snap, 0.0);
    rib.select(0.0);
    let backup_up = Snapshot { peers: [("backup".to_string(), PeerState::up(true))].into(), ..Default::default() };
    rib.update("edge", backup_up, 1.0);
    assert!(rib.select(1.0).is_empty());
}

#[test]
fn journal_restart_recovers_intents_and_fib_and_rejects_wrong_identity() {
    let config = demo();
    let directory = tempfile::tempdir().unwrap();
    let route = snapshot(&config, &source_data(&config)).routes[0].clone();
    {
        let journal = Journal::open(&config, Some(directory.path())).unwrap();
        journal.intent(&config.propagations[0].table, "10.20.1.0/24", &config.peers[0].eni).unwrap();
        journal.save_fib(&[(route.prefix.clone(), route.clone())].into()).unwrap();
    }
    let journal = Arc::new(Mutex::new(Journal::open(&config, Some(directory.path())).unwrap()));
    assert_eq!(journal.lock().unwrap().load_fib(&config).unwrap()[&route.prefix], route);
    assert_eq!(journal.lock().unwrap().entries().unwrap().len(), 1);
    drop(journal);
    let other = ServerConfig { id: "other".into(), ..config };
    assert!(Journal::open(&other, Some(directory.path())).is_err());
}
