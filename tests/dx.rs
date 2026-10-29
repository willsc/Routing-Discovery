use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use route_discovery::commands::Runner;
use route_discovery::dx::frr::{render, Plan, Policy, VIF_PREFIX_LIMIT};
use route_discovery::dx::vif::{link_name, resolve, BgpPeer, DirectConnect, Vif};
use route_discovery::dx::{announcements, local_addresses, vlan, Controller, Options};
use route_discovery::error::{Error, Result};
use route_discovery::mesh::inventory::{Filter, DEFAULT_EXCLUDE};
use serde_json::{json, Value};

fn peer(id: &str, amazon: &str, customer: &str) -> BgpPeer {
    BgpPeer {
        id: id.into(),
        asn: Some(65100),
        auth_key: Some("s3cret".into()),
        amazon_address: amazon.into(),
        customer_address: customer.into(),
        state: "available".into(),
    }
}

fn vif(id: &str, connection: &str, kind: &str, vlan: u16, peers: Vec<BgpPeer>) -> Vif {
    Vif {
        id: id.into(),
        region: "eu-west-2".into(),
        connection_id: connection.into(),
        kind: kind.into(),
        state: "available".into(),
        vlan,
        amazon_side_asn: Some(64512),
        mtu: Some(8500),
        peers,
    }
}

fn vifs() -> Vec<Vif> {
    let mut confirming = vif("dxvif-confirming", "dxcon-a", "private", 103, vec![peer("p3", "169.254.3.1/30", "169.254.3.2/30")]);
    confirming.state = "confirming".into();
    vec![
        // Already addressed on this router (no --port needed).
        vif("dxvif-private", "dxcon-other", "private", 101, vec![peer("p1", "169.254.1.1/30", "169.254.1.2/30")]),
        // Arrives on a mapped port; dual stack.
        vif(
            "dxvif-transit",
            "dxcon-a",
            "transit",
            102,
            vec![peer("p2", "169.254.2.1/30", "169.254.2.2/30"), peer("p2v6", "2001:db8:2::1/125", "2001:db8:2::2/125")],
        ),
        vif("dxvif-public", "dxcon-a", "public", 104, vec![peer("p4", "198.51.100.1/30", "198.51.100.2/30")]),
        confirming,
        // Someone else's VIF.
        vif("dxvif-foreign", "dxcon-z", "private", 105, vec![peer("p5", "169.254.5.1/30", "169.254.5.2/30")]),
    ]
}

fn ports() -> BTreeMap<String, String> {
    BTreeMap::from([("dxcon-a".to_string(), "eth1".to_string())])
}

fn interfaces() -> Value {
    let link = |name: &str, flags: &[&str], addresses: &[(&str, u8)]| {
        let info: Vec<Value> = addresses.iter().map(|(a, l)| json!({"local": a, "prefixlen": l})).collect();
        json!({"ifname": name, "flags": flags, "addr_info": info})
    };
    json!([
        link("lo", &["LOOPBACK", "UP"], &[("127.0.0.1", 8)]),
        link("eth0", &["UP"], &[("10.50.0.1", 24), ("fe80::1", 64)]),
        link("eth2", &["UP"], &[("10.60.0.1", 24), ("2001:db8:60::1", 64)]),
        link("eth3", &[], &[("10.70.0.1", 24)]),
        link("eth0.101", &["UP"], &[("169.254.1.2", 30)]),
        link("docker0", &["UP"], &[("172.17.0.1", 16)]),
        link("rddx999", &["UP"], &[("10.99.0.1", 30)]),
    ])
}

fn filter() -> Filter {
    Filter { include: vec![], exclude: DEFAULT_EXCLUDE.iter().map(|s| s.to_string()).collect() }
}

#[test]
fn resolves_vifs_this_router_terminates() {
    let found = resolve(&vifs(), &local_addresses(&interfaces()), &ports());
    let vifs: BTreeSet<&str> = found.neighbors.iter().map(|n| n.vif.as_str()).collect();
    assert_eq!(vifs, BTreeSet::from(["dxvif-private", "dxvif-transit"]));
    let transit: Vec<_> = found.neighbors.iter().filter(|n| n.vif == "dxvif-transit").collect();
    assert_eq!(transit.len(), 2);
    assert!(transit.iter().all(|n| n.interface == Some(link_name("eth1", 102)) && n.remote_asn == 64512 && n.local_asn == 65100));
    assert_eq!(found.links.len(), 1);
    assert_eq!(
        found.links[0].addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["169.254.2.2/30", "2001:db8:2::2/125"]
    );
    let ignored: BTreeMap<&str, &str> = found.ignored.iter().map(|i| (i.resource.as_str(), i.reason.as_str())).collect();
    assert!(ignored["dxvif-public"].contains("public"));
    assert!(ignored["dxvif-confirming"].contains("confirming"));
    assert!(!ignored.contains_key("dxvif-foreign"));
    // Stable across releases, unique per parent, and within IFNAMSIZ.
    assert_eq!(link_name("eth1", 102), "rddxf006.102");
    assert_ne!(link_name("eth1", 4094), link_name("eth2", 4094));
    assert!(link_name("enp129s0f1np1", 4094).len() <= 15);
}

#[test]
fn a_vlan_clashes_on_one_parent_but_not_across_parents() {
    let mut all = vifs();
    // Same VLAN as dxvif-transit: on the same parent it clashes, on a redundant connection it gets its own link.
    all.push(vif("dxvif-same-port", "dxcon-a", "private", 102, vec![peer("p6", "169.254.6.1/30", "169.254.6.2/30")]));
    all.push(vif("dxvif-other-port", "dxcon-b", "private", 102, vec![peer("p7", "169.254.7.1/30", "169.254.7.2/30")]));
    let mut ports = ports();
    ports.insert("dxcon-b".into(), "eth2".into());
    let found = resolve(&all, &local_addresses(&interfaces()), &ports);
    let links: BTreeMap<&str, &str> = found.links.iter().map(|l| (l.parent.as_str(), l.name.as_str())).collect();
    assert_eq!(links, BTreeMap::from([("eth1", link_name("eth1", 102).as_str()), ("eth2", link_name("eth2", 102).as_str())]));
    assert!(found.neighbors.iter().all(|n| n.vif != "dxvif-same-port"));
    assert!(found.neighbors.iter().any(|n| n.vif == "dxvif-other-port" && n.interface == Some(link_name("eth2", 102))));
    let ignored: BTreeMap<&str, &str> = found.ignored.iter().map(|i| (i.resource.as_str(), i.reason.as_str())).collect();
    assert!(ignored["dxvif-same-port"].contains("already used by dxvif-transit"));
    assert!(!ignored.contains_key("dxvif-other-port"));
}

#[test]
fn passwords_are_not_serialized() {
    let found = resolve(&vifs(), &local_addresses(&interfaces()), &ports());
    assert_eq!(found.neighbors[0].password.as_deref(), Some("s3cret"));
    assert!(!serde_json::to_string(&found).unwrap().contains("s3cret"));
}

#[test]
fn announces_on_prem_subnets_not_peering_links() {
    let found = resolve(&vifs(), &local_addresses(&interfaces()), &ports());
    let (announced, withheld) = announcements(&interfaces(), &filter(), &found).unwrap();
    let announced: Vec<String> = announced.iter().map(ToString::to_string).collect();
    assert_eq!(announced, ["10.50.0.0/24", "10.60.0.0/24", "2001:db8:60::/64"]);
    let withheld: BTreeMap<String, String> = withheld.iter().map(|w| (w.prefix.to_string(), w.reason.clone())).collect();
    assert!(withheld["10.70.0.0/24"].contains("down"));
    assert!(!withheld.contains_key("172.17.0.0/16"));
}

#[test]
fn bgpd_config_peers_every_vif() {
    let found = resolve(&vifs(), &local_addresses(&interfaces()), &ports());
    let announce = BTreeSet::from(["10.50.0.0/24".parse().unwrap(), "2001:db8:60::/64".parse().unwrap()]);
    let plan = |gated| {
        render(&Plan {
            router_id: "10.50.0.1".parse().unwrap(),
            neighbors: &found.neighbors,
            announce: &announce,
            gated,
            policy: &Policy::default(),
        })
    };
    let text = plan(false);
    for fragment in [
        "router bgp 65100",
        "neighbor 169.254.1.1 remote-as 64512",
        "neighbor 169.254.1.1 password s3cret",
        "neighbor 169.254.1.1 bfd",
        "neighbor 2001:db8:2::1 remote-as 64512",
        "address-family ipv6 unicast",
        "  network 2001:db8:60::/64",
        &format!("neighbor 169.254.2.1 maximum-prefix-out {VIF_PREFIX_LIMIT}"),
        "neighbor 169.254.2.1 route-map RDX-OUT-V4 out",
        "ip prefix-list RDX-IN-V4 seq 5 deny 10.50.0.0/24 le 32",
        "ip prefix-list RDX-IN-V4 seq 10 deny 0.0.0.0/0",
    ] {
        assert!(text.contains(fragment), "{fragment}\n{text}");
    }
    assert!(plan(true).contains("neighbor 169.254.1.1 route-map RDX-DENY out"));
    let idle = render(&Plan {
        router_id: "10.50.0.1".parse().unwrap(),
        neighbors: &[],
        announce: &announce,
        gated: false,
        policy: &Policy::default(),
    });
    assert!(!idle.contains("router bgp"));
}

#[test]
fn vlan_reconcile() {
    let found = resolve(&vifs(), &local_addresses(&interfaces()), &ports());
    let joined = |existing: &Value| -> Vec<String> {
        vlan::plan(&found.links, &vlan::parse(existing).unwrap()).iter().map(|c| c.join(" ")).collect()
    };
    assert_eq!(
        joined(&json!([])),
        [
            "ip link add link eth1 name rddxf006.102 type vlan id 102",
            "ip link set rddxf006.102 mtu 8500",
            "ip addr add 169.254.2.2/30 dev rddxf006.102",
            "ip addr add 2001:db8:2::2/125 dev rddxf006.102",
            "ip link set rddxf006.102 up",
        ]
    );
    let converged = json!([
        {"ifname": "rddxf006.102", "link": "eth1", "mtu": 8500, "flags": ["UP"], "linkinfo": {"info_kind": "vlan", "info_data": {"id": 102}},
         "addr_info": [{"local": "169.254.2.2", "prefixlen": 30}, {"local": "2001:db8:2::2", "prefixlen": 125}, {"local": "fe80::2", "prefixlen": 64}]},
        {"ifname": "rddx7", "link": "eth1", "flags": ["UP"], "linkinfo": {"info_kind": "vlan", "info_data": {"id": 7}}, "addr_info": []}
    ]);
    assert_eq!(joined(&converged), ["ip link del rddx7"]);
    let mut moved = converged.clone();
    moved[0]["link"] = json!("eth9");
    let commands = joined(&moved);
    assert_eq!(commands[1], "ip link del rddxf006.102");
    assert_eq!(commands[2], "ip link add link eth1 name rddxf006.102 type vlan id 102");
}

struct FakeDx(Vec<Vif>);

#[async_trait]
impl DirectConnect for FakeDx {
    async fn virtual_interfaces(&self) -> Result<Vec<Vif>> {
        Ok(self.0.clone())
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

fn controller(vifs: Vec<Vif>, apply: bool, dir: &std::path::Path) -> (Controller, Arc<Recorder>) {
    let runner = Arc::new(Recorder::default());
    let options = Options {
        regions: vec![],
        ports: ports(),
        filter: filter(),
        announce: vec![],
        policy: Policy::default(),
        frr_reload: "/usr/lib/frr/frr-reload.py".into(),
        vty_socket: None,
        interval: 30.0,
        listen: "127.0.0.1".parse().unwrap(),
        port: 0,
        state_dir: dir.to_path_buf(),
        apply,
    };
    (Controller::new(options, Arc::new(FakeDx(vifs)), runner.clone()), runner)
}

#[tokio::test]
async fn reconcile_creates_links_then_reloads_with_private_config() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (c, runner) = controller(vifs(), true, dir.path());
    let o = c.observe().await.unwrap();
    assert!(o.gated.is_none());
    assert!(c.reconcile(&o).await.unwrap());
    assert!(c.reconcile(&o).await.unwrap());
    let calls = runner.0.lock().unwrap().clone();
    let reload = calls.iter().position(|c| c.contains("--reload")).unwrap();
    assert_eq!(calls.iter().filter(|c| c.contains("--reload")).count(), 1);
    assert!(calls.iter().position(|c| c.starts_with("ip link add link eth1")).unwrap() < reload);
    let path = dir.path().join("bgpd.conf");
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(std::fs::read_to_string(path).unwrap().contains("password s3cret"));
    // The rddx999 link is owned and not wanted.
    assert!(calls.iter().any(|c| c == "ip link del rddx999"));
}

#[tokio::test]
async fn over_the_prefix_limit_withholds_announcements() {
    let dir = tempfile::tempdir().unwrap();
    let (c, _) = controller(vifs(), false, dir.path());
    let mut options = c.options.clone();
    options.announce =
        (0..=VIF_PREFIX_LIMIT).map(|i| format!("10.{}.{}.0/24", 100 + i / 256, i % 256).parse().unwrap()).collect();
    let c = Controller::new(options, Arc::new(FakeDx(vifs())), Arc::new(Recorder::default()));
    let o = c.observe().await.unwrap();
    assert!(o.gated.as_deref().unwrap().contains("limit of 100"));
    assert!(o.config.contains("route-map RDX-DENY out"));
    assert!(!o.config.contains("route-map RDX-OUT-V4 out"));
}

#[tokio::test]
async fn dry_run_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (c, runner) = controller(vifs(), false, dir.path());
    let o = c.observe().await.unwrap();
    assert!(!c.reconcile(&o).await.unwrap());
    assert!(runner.0.lock().unwrap().iter().all(|c| c.starts_with("ip -d")));
}

#[tokio::test]
async fn withdraw_clears_bgpd_and_links() {
    let dir = tempfile::tempdir().unwrap();
    let (c, runner) = controller(vifs(), true, dir.path());
    route_discovery::dx::withdraw(&c).await.unwrap();
    let calls = runner.0.lock().unwrap().clone();
    assert!(calls[0].contains("--reload"));
    assert!(calls.iter().any(|c| c == "ip link del rddx999"));
    assert!(!std::fs::read_to_string(dir.path().join("bgpd.conf")).unwrap().contains("router bgp"));
}
