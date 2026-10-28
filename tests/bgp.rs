use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use route_discovery::bgp::advertise::{default_filter, select};
use route_discovery::bgp::discovery::{resolve, tunnel_name, ConnectBgp, ConnectPeer, Kind, Peering, RouteServerPeer};
use route_discovery::bgp::frr::{parse_summary, render, Plan, Policy};
use route_discovery::bgp::metadata::{host, Host, Metadata};
use route_discovery::bgp::{gre, Controller, Options};
use route_discovery::commands::Runner;
use route_discovery::error::{Error, Result};
use serde_json::{json, Value};

const MAC_A: &str = "0a:00:00:00:00:01";
const MAC_B: &str = "0a:00:00:00:00:02";

struct FakeImds(BTreeMap<String, String>);

impl FakeImds {
    fn new() -> Self {
        let mut m = BTreeMap::new();
        let mut put = |k: &str, v: &str| {
            m.insert(k.to_string(), v.to_string());
        };
        put("meta-data/instance-id", "i-0123456789abcdef0");
        put("meta-data/placement/region", "eu-west-2");
        let base = "meta-data/network/interfaces/macs";
        put(&format!("{base}/"), &format!("{MAC_A}/\n{MAC_B}/"));
        for (mac, eni, subnet, ips) in
            [(MAC_A, "eni-a", "subnet-a", "10.0.1.10"), (MAC_B, "eni-b", "subnet-b", "10.0.2.10\n10.0.2.11")]
        {
            put(&format!("{base}/{mac}/vpc-id"), "vpc-1");
            put(&format!("{base}/{mac}/vpc-ipv4-cidr-blocks"), "10.0.0.0/16");
            put(&format!("{base}/{mac}/interface-id"), eni);
            put(&format!("{base}/{mac}/subnet-id"), subnet);
            put(&format!("{base}/{mac}/local-ipv4s"), ips);
        }
        FakeImds(m)
    }
}

#[async_trait]
impl Metadata for FakeImds {
    async fn get(&self, path: &str) -> Result<Option<String>> {
        Ok(self.0.get(path).cloned())
    }
}

fn rs_peer(id: &str, peer: &str, endpoint: &str) -> RouteServerPeer {
    RouteServerPeer {
        id: id.into(),
        route_server_id: "rs-1".into(),
        vpc_id: "vpc-1".into(),
        state: "available".into(),
        endpoint_address: endpoint.into(),
        peer_address: peer.into(),
        peer_asn: Some(65010),
        liveness: Some("bfd".into()),
    }
}

fn connect_peer() -> ConnectPeer {
    ConnectPeer {
        id: "tgw-connect-peer-0123456789abcdef0".into(),
        state: "available".into(),
        transit_gateway_address: "192.0.2.10".into(),
        peer_address: "10.0.2.10".into(),
        inside_cidrs: vec!["169.254.6.0/29".into()],
        protocol: "gre".into(),
        bgp: ["169.254.6.2", "169.254.6.3"]
            .iter()
            .map(|tgw| ConnectBgp {
                transit_gateway_asn: Some(64512),
                peer_asn: Some(65020),
                transit_gateway_address: tgw.to_string(),
                peer_address: "169.254.6.1".into(),
            })
            .collect(),
    }
}

fn route_servers() -> Vec<RouteServerPeer> {
    let mut other_vpc = rs_peer("rsp-other", "10.0.1.10", "10.0.1.250");
    other_vpc.vpc_id = "vpc-2".into();
    let mut pending = rs_peer("rsp-pending", "10.0.2.11", "10.0.2.250");
    pending.state = "pending".into();
    vec![rs_peer("rsp-a", "10.0.1.10", "10.0.1.230"), rs_peer("rsp-elsewhere", "10.0.9.9", "10.0.9.230"), other_vpc, pending]
}

fn asns() -> BTreeMap<String, i64> {
    BTreeMap::from([("rs-1".to_string(), 65000)])
}

async fn test_host() -> Host {
    host(&FakeImds::new()).await.unwrap()
}

fn interfaces() -> Value {
    let link = |name: &str, flags: &[&str], addresses: &[(&str, u8)]| {
        let info: Vec<Value> = addresses.iter().map(|(a, l)| json!({"local": a, "prefixlen": l})).collect();
        json!({"ifname": name, "flags": flags, "addr_info": info})
    };
    json!([
        link("lo", &["LOOPBACK", "UP"], &[("127.0.0.1", 8), ("10.200.0.10", 32), ("::1", 128)]),
        link("eth0", &["UP"], &[("10.0.1.10", 24), ("fe80::1", 64)]),
        link("dummy0", &["UP"], &[("192.168.50.1", 24)]),
        link("dummy1", &[], &[("192.168.60.1", 24)]),
        link("docker0", &["UP"], &[("172.17.0.1", 16)]),
        link("rdgre123456789", &["UP"], &[("169.254.6.1", 29)]),
    ])
}

#[tokio::test]
async fn host_from_imds() {
    let h = test_host().await;
    assert_eq!(h.vpc_id, "vpc-1");
    assert_eq!(h.enis.len(), 2);
    assert_eq!(h.eni_of("10.0.2.11".parse().unwrap()).unwrap().id, "eni-b");
    assert_eq!(h.router_id().unwrap().to_string(), "10.0.1.10");
    let mut imds = FakeImds::new();
    imds.0.insert(format!("meta-data/network/interfaces/macs/{MAC_B}/vpc-id"), "vpc-2".into());
    assert!(host(&imds).await.is_err());
}

#[tokio::test]
async fn discovery_matches_only_this_instance() {
    let found = resolve(&test_host().await, &route_servers(), &asns(), &[connect_peer()]);
    let rs: Vec<_> = found.neighbors.iter().filter(|n| n.kind == Kind::RouteServer).collect();
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].address.to_string(), "10.0.1.230");
    assert_eq!((rs[0].local_asn, rs[0].remote_asn, rs[0].bfd), (65010, 65000, true));
    assert_eq!(rs[0].eni.as_deref(), Some("eni-a"));
    let ignored: BTreeSet<&str> = found.ignored.iter().map(|i| i.resource.as_str()).collect();
    assert_eq!(ignored, BTreeSet::from(["rsp-other", "rsp-pending"]));
    let tgw: Vec<_> = found.neighbors.iter().filter(|n| n.kind == Kind::TgwConnect).collect();
    assert_eq!(tgw.len(), 2);
    assert!(tgw.iter().all(|n| n.multihop == Some(2) && n.eni.is_none()));
    assert_eq!(found.tunnels.len(), 1);
    assert_eq!(found.tunnels[0].inside[0].to_string(), "169.254.6.1/29");
    assert_eq!(found.tunnels[0].remote.to_string(), "192.0.2.10");
}

#[test]
fn tunnel_names_fit_ifnamsiz() {
    let name = tunnel_name("tgw-connect-peer-0123456789abcdef0");
    assert_eq!(name, "rdgre89abcdef0");
    assert!(name.len() <= 15);
}

#[tokio::test]
async fn announces_service_addresses_outside_the_vpc() {
    let a = select(&interfaces(), &default_filter(), &test_host().await).unwrap();
    let announced: Vec<String> = a.prefixes.iter().map(ToString::to_string).collect();
    assert_eq!(announced, ["10.200.0.10/32", "192.168.50.0/24"]);
    let withheld: BTreeMap<String, String> = a.withheld.iter().map(|w| (w.prefix.to_string(), w.reason.clone())).collect();
    assert!(withheld["10.0.1.0/24"].contains("VPC"));
    assert!(withheld["192.168.60.0/24"].contains("down"));
    assert!(!withheld.contains_key("172.17.0.0/16"));
}

fn plan_text(
    gated: &BTreeSet<IpAddr>,
    announce: &BTreeSet<ipnet::IpNet>,
    found: &[route_discovery::bgp::discovery::Neighbor],
) -> String {
    render(&Plan {
        router_id: "10.0.1.10".parse().unwrap(),
        neighbors: found,
        announce,
        vpc_cidrs: &["10.0.0.0/16".parse().unwrap()],
        gated,
        policy: &Policy::default(),
    })
}

#[tokio::test]
async fn bgpd_config() {
    let found = resolve(&test_host().await, &route_servers(), &asns(), &[connect_peer()]);
    let announce = BTreeSet::from(["10.200.0.10/32".parse().unwrap()]);
    let gated = BTreeSet::from(["10.0.1.230".parse().unwrap()]);
    let text = plan_text(&gated, &announce, &found.neighbors);
    for fragment in [
        "router bgp 65020",
        "neighbor 10.0.1.230 remote-as 65000",
        "neighbor 10.0.1.230 local-as 65010 no-prepend replace-as",
        "neighbor 10.0.1.230 bfd",
        "neighbor 10.0.1.230 route-map RDB-DENY out",
        "neighbor 169.254.6.2 ebgp-multihop 2",
        "neighbor 169.254.6.3 route-map RDB-OUT-V4 out",
        "network 10.200.0.10/32",
        "ip prefix-list RDB-IN-V4 seq 5 deny 10.0.0.0/16 le 32",
        "ip prefix-list RDB-OUT-V4 seq 5 permit 10.200.0.10/32",
        "maximum-paths 4",
    ] {
        assert!(text.contains(fragment), "{fragment}\n{text}");
    }
    assert!(!text.contains("address-family ipv6"));
    let idle = plan_text(&BTreeSet::new(), &announce, &[]);
    assert!(!idle.contains("router bgp"));
    assert!(idle.contains("RDB-OUT-V4"));
}

#[tokio::test]
async fn gre_reconcile() {
    let found = resolve(&test_host().await, &[], &asns(), &[connect_peer()]);
    let commands = gre::plan(&found.tunnels, &BTreeMap::new());
    let joined: Vec<String> = commands.iter().map(|c| c.join(" ")).collect();
    assert_eq!(
        joined,
        [
            "ip link add rdgre89abcdef0 type gre local 10.0.2.10 remote 192.0.2.10 ttl 255",
            "ip addr add 169.254.6.1/29 dev rdgre89abcdef0",
            "ip link set rdgre89abcdef0 up",
        ]
    );
    let existing = json!([
        {"ifname": "rdgre89abcdef0", "flags": ["UP"], "linkinfo": {"info_kind": "gre", "info_data": {"local": "10.0.2.10", "remote": "192.0.2.10"}},
         "addr_info": [{"local": "169.254.6.1", "prefixlen": 29}, {"local": "fe80::1", "prefixlen": 64}]},
        {"ifname": "rdgreold", "flags": ["UP"], "linkinfo": {"info_kind": "gre", "info_data": {}}, "addr_info": []},
        {"ifname": "gre0", "flags": [], "addr_info": []}
    ]);
    let joined: Vec<String> = gre::plan(&found.tunnels, &gre::parse(&existing).unwrap()).iter().map(|c| c.join(" ")).collect();
    assert_eq!(joined, ["ip link del rdgreold"]);
    let mut moved = existing.clone();
    moved[0]["linkinfo"]["info_data"]["remote"] = json!("192.0.2.99");
    let joined: Vec<String> = gre::plan(&found.tunnels, &gre::parse(&moved).unwrap()).iter().map(|c| c.join(" ")).collect();
    assert_eq!(joined[1], "ip link del rdgre89abcdef0");
    assert!(joined[2].starts_with("ip link add rdgre89abcdef0"));
}

#[test]
fn sessions_from_summary() {
    let data = json!({"ipv4Unicast": {"peers": {"10.0.1.230": {"state": "Established", "pfxRcd": 3, "pfxSnt": 1}}},
                      "ipv6Unicast": {"peers": {"2001:db8::1": {"state": "Active"}}}});
    let sessions = parse_summary(&data).unwrap();
    assert_eq!(sessions["10.0.1.230"].received, Some(3));
    assert_eq!(sessions["2001:db8::1"].state, "Active");
    assert!(parse_summary(&json!([])).is_err());
}

struct FakeAws {
    checks: bool,
}

#[async_trait]
impl Peering for FakeAws {
    async fn route_server_peers(&self) -> Result<Vec<RouteServerPeer>> {
        Ok(route_servers())
    }
    async fn route_server_asns(&self, _ids: &[String]) -> Result<BTreeMap<String, i64>> {
        Ok(asns())
    }
    async fn connect_peers(&self) -> Result<Vec<ConnectPeer>> {
        Ok(vec![connect_peer()])
    }
    async fn source_dest_checks(&self, ids: &[String]) -> Result<BTreeMap<String, bool>> {
        Ok(ids.iter().map(|id| (id.clone(), self.checks)).collect())
    }
}

#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

#[async_trait]
impl Runner for Recorder {
    async fn run(&self, args: &[String], _timeout: f64) -> Result<String> {
        self.0.lock().unwrap().push(args.join(" "));
        match args[0].as_str() {
            "ip" if args[1] == "-d" => Ok(interfaces().to_string()),
            "ip" => Ok(String::new()),
            "vtysh" => Ok(json!({}).to_string()),
            program if program.ends_with("frr-reload.py") => Ok(String::new()),
            _ => Err(Error::Backend("unexpected".into())),
        }
    }
}

fn controller(checks: bool, apply: bool, dir: &std::path::Path) -> (Controller, Arc<Recorder>) {
    let runner = Arc::new(Recorder::default());
    let options = Options {
        filter: default_filter(),
        policy: Policy::default(),
        frr_reload: "/usr/lib/frr/frr-reload.py".into(),
        vty_socket: None,
        interval: 15.0,
        listen: "127.0.0.1".parse().unwrap(),
        port: 0,
        state_dir: dir.to_path_buf(),
        apply,
    };
    let c = Controller::new(options, Arc::new(FakeImds::new()), Arc::new(FakeAws { checks }), runner.clone());
    (c, runner)
}

#[tokio::test]
async fn source_dest_check_gates_route_server_announcements() {
    let dir = tempfile::tempdir().unwrap();
    let (c, _) = controller(true, false, dir.path());
    let o = c.observe().await.unwrap();
    assert!(o.gated.contains_key(&"10.0.1.230".parse::<IpAddr>().unwrap()));
    assert!(o.config.contains("neighbor 10.0.1.230 route-map RDB-DENY out"));
    // GRE-delivered traffic is addressed to the ENI itself; TGW Connect is not gated.
    assert!(o.config.contains("neighbor 169.254.6.2 route-map RDB-OUT-V4 out"));
    let (c, _) = controller(false, false, dir.path());
    assert!(c.observe().await.unwrap().gated.is_empty());
}

#[tokio::test]
async fn reconcile_reloads_once_and_creates_tunnels_first() {
    let dir = tempfile::tempdir().unwrap();
    let (c, runner) = controller(false, true, dir.path());
    let o = c.observe().await.unwrap();
    assert!(c.reconcile(&o).await.unwrap());
    assert!(c.reconcile(&o).await.unwrap());
    let calls = runner.0.lock().unwrap().clone();
    let reloads: Vec<&String> = calls.iter().filter(|c| c.contains("--reload")).collect();
    assert_eq!(reloads.len(), 1);
    assert!(reloads[0].ends_with("bgpd.conf") && reloads[0].contains("--daemon bgpd"));
    let first_reload = calls.iter().position(|c| c.contains("--reload")).unwrap();
    let tunnel = calls.iter().position(|c| c.starts_with("ip link add rdgre")).unwrap();
    assert!(tunnel < first_reload);
    let written = std::fs::read_to_string(dir.path().join("bgpd.conf")).unwrap();
    assert_eq!(written, o.config);
}

#[tokio::test]
async fn dry_run_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (c, runner) = controller(false, false, dir.path());
    let o = c.observe().await.unwrap();
    assert!(!c.reconcile(&o).await.unwrap());
    assert!(runner.0.lock().unwrap().iter().all(|c| c.starts_with("ip -d") || c.starts_with("vtysh")));
}
