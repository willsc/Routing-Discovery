use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};

use route_discovery::commands::Runner;
use route_discovery::error::{Error, Result};
use route_discovery::mesh::frr::{desired, plan, Direction, Policy, Running};
use route_discovery::mesh::inventory::{parse, Filter};
use route_discovery::mesh::overlay::registry::{key_of, parse_url, Entry, Object, Platform, Registry, Store};
use route_discovery::mesh::overlay::select::select;
use route_discovery::mesh::overlay::underlay::{self, Pin};
use route_discovery::mesh::overlay::{self, metal_identity, peers, tunnel, Overlay, PlatformChoice};
use route_discovery::mesh::{Mesh, Options};

fn entry(host: &str, site: &str, endpoint: &str, since: i64) -> Entry {
    Entry {
        host: host.into(),
        name: format!("{host}.example"),
        site: site.into(),
        platform: if site.starts_with("vpc-") { Platform::Ec2 } else { Platform::Metal },
        endpoint: endpoint.parse().unwrap(),
        since,
    }
}

/// Two VPCs with three hosts each, and one bare-metal host.
fn fleet() -> Vec<(Entry, i64)> {
    vec![
        (entry("i-a1", "vpc-a", "10.1.0.11", 100), 10),
        (entry("i-a2", "vpc-a", "10.1.0.12", 200), 10),
        (entry("i-a3", "vpc-a", "10.1.0.13", 300), 10),
        (entry("i-b1", "vpc-b", "10.2.0.11", 100), 10),
        (entry("i-b2", "vpc-b", "10.2.0.12", 150), 10),
        (entry("i-b3", "vpc-b", "10.2.0.13", 50), 900),
        (entry("metal-1", "metal-1", "192.168.50.5", 10), 10),
    ]
}

fn hosts(entries: &[Entry]) -> Vec<&str> {
    entries.iter().map(|e| e.host.as_str()).collect()
}

#[test]
fn relays_are_the_most_senior_live_hosts_of_each_site() {
    let all = fleet();
    let member = select(&all[2].0, &all, 300, 2);
    assert!(!member.relay);
    assert_eq!(member.relays["vpc-a"], ["i-a1", "i-a2"]);
    // i-b3 is the most senior but silent for 900 s, so it is skipped.
    assert_eq!(member.relays["vpc-b"], ["i-b1", "i-b2"]);
    assert!(member.stale.iter().any(|s| s.starts_with("i-b3")));
    // A host that is not a relay only tunnels to its own site's relays.
    assert_eq!(hosts(&member.peers), ["i-a1", "i-a2"]);
}

#[test]
fn relays_tunnel_to_other_sites_relays_and_their_own_members() {
    let all = fleet();
    let relay = select(&all[0].0, &all, 300, 2);
    assert!(relay.relay);
    assert_eq!(hosts(&relay.peers), ["i-a2", "i-a3", "i-b1", "i-b2", "metal-1"]);
    // A host outside AWS is a site of its own, so it is always a relay.
    let metal = select(&all[6].0, &all, 300, 2);
    assert!(metal.relay);
    assert_eq!(hosts(&metal.peers), ["i-a1", "i-a2", "i-b1", "i-b2"]);
}

#[test]
fn tunnel_names_and_link_locals_are_stable() {
    assert_eq!(tunnel::tunnel_name("i-a1"), tunnel::tunnel_name("i-a1"));
    assert_ne!(tunnel::tunnel_name("i-a1"), tunnel::tunnel_name("i-a2"));
    assert!(tunnel::tunnel_name("metal-0123456789abcdef").len() <= 15);
    let ll = tunnel::link_local("i-a1");
    assert!(ll.is_unicast_link_local());
    assert_ne!(ll, tunnel::link_local("i-a2"));
    // IPv4 next hops inside tunnels are link-local and avoid AWS's 169.254.169.x and 169.254.170.x services.
    for i in 0..5000 {
        let inner = tunnel::inner_v4(&format!("i-{i:017x}"));
        assert!(
            inner.is_link_local() && !matches!(inner.octets()[2], 0 | 169 | 170 | 255) && !matches!(inner.octets()[3], 0 | 255)
        );
    }
}

#[test]
fn tunnels_are_created_then_converge() {
    let peers = vec![entry("i-b1", "vpc-b", "10.2.0.11", 100)];
    let own = entry("i-a1", "vpc-a", "10.1.0.11", 100);
    let (tunnels, skipped) = tunnel::desired(&own, &peers);
    assert!(skipped.is_empty());
    let name = tunnel::tunnel_name("i-b1");
    let ll = tunnel::link_local("i-a1");
    let (inner, peer) = (tunnel::inner_v4("i-a1"), tunnel::inner_v4("i-b1"));
    let stale = json!([{"ifname": "rdm00000000", "flags": ["UP"], "linkinfo": {"info_kind": "gre"}, "addr_info": []}]);
    let commands: Vec<String> =
        tunnel::plan(&tunnels, &tunnel::parse(&stale).unwrap(), ll, 1476).iter().map(|c| c.join(" ")).collect();
    assert_eq!(
        commands,
        [
            "ip link del rdm00000000".to_string(),
            format!("ip link add {name} type gre local 10.1.0.11 remote 10.2.0.11 ttl 255"),
            format!("ip link set {name} mtu 1476"),
            format!("ip link set {name} multicast on"),
            format!("ip addr add {ll}/64 dev {name}"),
            format!("ip addr add {inner}/32 peer {peer}/32 dev {name}"),
            format!("ip link set {name} up"),
        ]
    );
    let converged = json!([{
        "ifname": name, "mtu": 1476, "flags": ["POINTOPOINT", "MULTICAST", "NOARP", "UP"],
        "linkinfo": {"info_kind": "gre", "info_data": {"local": "10.1.0.11", "remote": "10.2.0.11"}},
        "addr_info": [{"local": ll.to_string(), "prefixlen": 64},
                      {"local": inner.to_string(), "address": peer.to_string(), "prefixlen": 32}]
    }]);
    assert!(tunnel::plan(&tunnels, &tunnel::parse(&converged).unwrap(), ll, 1476).is_empty());
    // A stray IPv4 address on an owned tunnel is removed with its real prefix length.
    let mut stray = converged.clone();
    stray[0]["addr_info"].as_array_mut().unwrap().push(json!({"local": "169.254.99.1", "prefixlen": 30}));
    let commands: Vec<String> =
        tunnel::plan(&tunnels, &tunnel::parse(&stray).unwrap(), ll, 1476).iter().map(|c| c.join(" ")).collect();
    assert_eq!(commands, [format!("ip addr del 169.254.99.1/30 dev {name}")]);
}

/// An EC2 host's main table once Babel has learned the remote VPC over a tunnel.
fn main_table() -> Value {
    let tunnel = tunnel::tunnel_name("i-b1");
    json!([
        {"dst": "default", "gateway": "10.1.0.1", "dev": "ens5", "protocol": "dhcp", "metric": 100},
        {"dst": "10.1.0.0/24", "dev": "ens5", "protocol": "kernel", "scope": "link"},
        {"dst": "10.2.0.0/16", "nhid": 12, "gateway": "fe80::1", "dev": tunnel, "protocol": "babel", "metric": 20},
        {"dst": "10.3.0.0/16", "nhid": 13, "protocol": "babel", "metric": 20,
         "nexthops": [{"gateway": "10.1.0.1", "dev": "ens5"}]},
        {"dst": "192.168.50.0/24", "type": "blackhole", "protocol": "static"}
    ])
}

#[test]
fn endpoints_are_pinned_to_the_underlay_never_the_overlay() {
    let main = underlay::parse_routes(&main_table()).unwrap();
    let via_vpc_router = Pin::Via { gateway: Some("10.1.0.1".parse().unwrap()), dev: "ens5".into() };
    // The Babel route for 10.2/16 points into a tunnel; the endpoint must use the VPC router instead.
    assert_eq!(underlay::underlay_pin(&main, "10.2.0.11".parse().unwrap()), via_vpc_router);
    // Any Babel route is overlay, even one whose next hop looks physical.
    assert_eq!(underlay::underlay_pin(&main, "10.3.0.11".parse().unwrap()), via_vpc_router);
    assert_eq!(underlay::underlay_pin(&main, "10.1.0.12".parse().unwrap()), Pin::Via { gateway: None, dev: "ens5".into() });
    assert_eq!(underlay::underlay_pin(&main, "192.168.50.5".parse().unwrap()), Pin::Unreachable);
    let no_default: Vec<_> = main.iter().filter(|r| r.dst.prefix_len() != 0).cloned().collect();
    assert_eq!(underlay::underlay_pin(&no_default, "172.31.0.1".parse().unwrap()), Pin::Unreachable);
}

#[test]
fn pins_rule_and_originated_routes_plan_then_converge() {
    let main = underlay::parse_routes(&main_table()).unwrap();
    let endpoints: BTreeSet<Ipv4Addr> = ["10.2.0.11".parse().unwrap(), "192.168.50.5".parse().unwrap()].into();
    let wanted = underlay::desired(&main, &endpoints, &["10.1.0.0/16".parse().unwrap()]);
    let stale = underlay::parse_routes(&json!([{"dst": "10.9.9.9", "gateway": "10.1.0.1", "dev": "ens5"}])).unwrap();
    let commands: Vec<String> = underlay::plan(&wanted, &stale, &main, false).iter().map(|c| c.join(" ")).collect();
    assert_eq!(
        commands,
        [
            "ip rule add priority 4242 ipproto 47 lookup 4242",
            "ip route del 10.9.9.9/32 table 4242",
            "ip route replace 10.2.0.11/32 via 10.1.0.1 dev ens5 table 4242 proto 249",
            "ip route replace unreachable 192.168.50.5/32 table 4242 proto 249",
            "ip route replace 10.1.0.0/16 via 10.1.0.1 dev ens5 proto 249",
        ]
    );
    let pinned = underlay::parse_routes(&json!([
        {"dst": "10.2.0.11", "gateway": "10.1.0.1", "dev": "ens5", "protocol": "249"},
        {"dst": "192.168.50.5", "type": "unreachable", "protocol": "249"}
    ]))
    .unwrap();
    let mut with_origin = main_table();
    with_origin
        .as_array_mut()
        .unwrap()
        .push(json!({"dst": "10.1.0.0/16", "gateway": "10.1.0.1", "dev": "ens5", "protocol": "249"}));
    let main = underlay::parse_routes(&with_origin).unwrap();
    let rules = json!([{"priority": 4242, "src": "all", "ipproto": "gre", "table": "4242"}]);
    assert!(underlay::has_rule(&rules));
    assert!(underlay::plan(&wanted, &pinned, &main, true).is_empty());
    // Losing the relay role removes the originated route.
    let member = underlay::desired(&main, &endpoints, &[]);
    let commands: Vec<String> = underlay::plan(&member, &pinned, &main, true).iter().map(|c| c.join(" ")).collect();
    assert_eq!(commands, ["ip route del 10.1.0.0/16 proto 249"]);
}

fn tunnel_host() -> Value {
    json!([
        {"ifname": "ens5", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP",
         "addr_info": [{"local": "10.1.0.11", "prefixlen": 24}, {"local": "fe80::1", "prefixlen": 64}]},
        {"ifname": tunnel::tunnel_name("i-b1"), "flags": ["POINTOPOINT", "MULTICAST", "NOARP", "UP", "LOWER_UP"], "operstate": "UNKNOWN",
         "addr_info": [{"local": tunnel::link_local("i-a1").to_string(), "prefixlen": 64}]}
    ])
}

fn filter_entries(policy: &Policy, filter: &Filter) -> BTreeMap<(Direction, u8), Vec<String>> {
    desired(&parse(&tunnel_host(), filter, &|_| false).unwrap(), policy).filters
}

#[test]
fn vpc_hosts_never_learn_their_own_vpc_and_members_carry_no_transit() {
    let ec2 = Filter { include: vec!["rdm*".into()], exclude: vec![] };
    let member = Policy { local: vec!["10.1.0.0/16".parse().unwrap()], leaf: true, ..Policy::default() };
    let filters = filter_entries(&member, &ec2);
    assert_eq!(filters[&(Direction::Out, 4)], ["deny any"]);
    assert_eq!(filters[&(Direction::In, 4)][0], "deny 10.1.0.0/16 le 32");
    let inventory = parse(&tunnel_host(), &ec2, &|_| false).unwrap();
    assert_eq!(inventory.nics.len(), 1, "only the tunnel carries Babel on EC2");
    assert_eq!(inventory.withheld, ["10.1.0.0/24".parse().unwrap()]);
}

#[test]
fn relays_originate_their_vpc_through_kernel_redistribution() {
    let ec2 = Filter { include: vec!["rdm*".into()], exclude: vec![] };
    let relay = Policy {
        local: vec!["10.1.0.0/16".parse().unwrap()],
        originate: vec!["10.1.0.0/16".parse().unwrap()],
        ..Policy::default()
    };
    let wanted = desired(&parse(&tunnel_host(), &ec2, &|_| false).unwrap(), &relay);
    assert!(wanted.redistribute.contains("redistribute ipv4 kernel"));
    let out = &wanted.filters[&(Direction::Out, 4)];
    // The subnet NIC is withheld; the whole VPC is advertised instead.
    assert_eq!(out[0], "deny 10.1.0.0/24");
    assert!(out.contains(&"permit 10.1.0.0/16".to_string()));
    // When the relay role moves away, kernel redistribution is removed again.
    let running = Running { router: true, redistribute: wanted.redistribute.clone(), ..Running::default() };
    let member = desired(&parse(&tunnel_host(), &ec2, &|_| false).unwrap(), &Policy { leaf: true, ..Policy::default() });
    assert!(plan(&member, &running).contains(&"no redistribute ipv4 kernel".to_string()));
}

#[test]
fn metal_identity_uses_machine_id_and_default_path_source() {
    let options = overlay_options();
    let route = json!([{"dst": "192.0.2.1", "gateway": "192.168.50.1", "dev": "eno1", "prefsrc": "192.168.50.5"}]);
    let own = metal_identity("0123456789abcdef0123456789abcdef\n", "db1\n", &route, &options).unwrap();
    assert_eq!(own.host, "metal-0123456789abcdef");
    assert_eq!(own.site, own.host);
    assert_eq!(own.name, "db1");
    assert_eq!(own.endpoint, "192.168.50.5".parse::<Ipv4Addr>().unwrap());
    assert!(metal_identity("", "db1", &route, &options).is_err());
}

#[test]
fn registry_urls() {
    assert_eq!(parse_url("s3://bucket/mesh/prod/").unwrap(), ("bucket".into(), "mesh/prod".into()));
    assert_eq!(parse_url("s3://bucket").unwrap(), ("bucket".into(), String::new()));
    assert!(parse_url("https://bucket").is_err());
}

#[derive(Default)]
struct FakeStore {
    objects: Mutex<BTreeMap<String, (Vec<u8>, i64)>>,
    gets: Mutex<Vec<String>>,
    puts: Mutex<usize>,
    clock: Mutex<i64>,
}

impl FakeStore {
    fn add(&self, e: &Entry, modified: i64) {
        self.objects.lock().unwrap().insert(key_of(&e.host), (serde_json::to_vec(e).unwrap(), modified));
    }
}

#[async_trait]
impl Store for FakeStore {
    async fn list(&self) -> Result<Vec<Object>> {
        Ok(self
            .objects
            .lock()
            .unwrap()
            .iter()
            .map(|(key, (body, modified))| Object {
                key: key.clone(),
                etag: format!("{:x}", body.len() * 31 + body[10] as usize),
                modified: *modified,
            })
            .collect())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.gets.lock().unwrap().push(key.to_string());
        Ok(self.objects.lock().unwrap().get(key).map(|(b, _)| b.clone()))
    }

    async fn put(&self, key: &str, body: Vec<u8>) -> Result<()> {
        *self.puts.lock().unwrap() += 1;
        let now = *self.clock.lock().unwrap();
        self.objects.lock().unwrap().insert(key.to_string(), (body, now));
        Ok(())
    }
}

#[tokio::test]
async fn registry_sync_publishes_ages_by_s3_time_and_fetches_only_changes() {
    let store = FakeStore::default();
    *store.clock.lock().unwrap() = 10_000;
    store.add(&entry("i-b1", "vpc-b", "10.2.0.11", 100), 9_990);
    store.add(&entry("i-b2", "vpc-b", "10.2.0.12", 100), 9_000);
    let own = entry("i-a1", "vpc-a", "10.1.0.11", 100);
    let mut registry = Registry::default();
    // The local clock is far off; ages come from S3's LastModified relative to this host's own write.
    let seen = registry.sync(&store, &own, true, 50).await.unwrap();
    let ages: BTreeMap<&str, i64> = seen.iter().map(|(e, age)| (e.host.as_str(), *age)).collect();
    assert_eq!(ages, BTreeMap::from([("i-a1", 0), ("i-b1", 10), ("i-b2", 1000)]));
    assert_eq!(*store.puts.lock().unwrap(), 1);
    store.gets.lock().unwrap().clear();
    registry.sync(&store, &own, true, 60).await.unwrap();
    assert!(store.gets.lock().unwrap().is_empty(), "unchanged entries are served from the cache");
    // A dry run reads but never writes.
    let fresh = FakeStore::default();
    let seen = Registry::default().sync(&fresh, &own, false, 50).await.unwrap();
    assert_eq!(*fresh.puts.lock().unwrap(), 0);
    assert_eq!(hosts(&seen.into_iter().map(|(e, _)| e).collect::<Vec<_>>()), ["i-a1"]);
}

fn overlay_options() -> overlay::Options {
    overlay::Options {
        source: overlay::Source::Registry { url: "s3://bucket/mesh".into(), region: None },
        platform: PlatformChoice::Ec2,
        site: None,
        endpoint: None,
        relays: 2,
        interval: 60.0,
        mtu: 1476,
    }
}

/// A fake EC2 host: canned `ip` and vtysh reads, every other command recorded.
struct Host {
    calls: Mutex<Vec<String>>,
    /// A fresh host: table 4242 doesn't exist until its first route.
    fresh: bool,
}

#[async_trait]
impl Runner for Host {
    async fn run(&self, args: &[String], _timeout: f64) -> Result<String> {
        let line = args.join(" ");
        self.calls.lock().unwrap().push(line.clone());
        if self.fresh && line == "ip -json route show table 4242" {
            return Err(Error::Backend("ip exited 2: Error: ipv4: FIB table does not exist.\nDump terminated".into()));
        }
        Ok(match line.as_str() {
            "ip -json addr show" => tunnel_host().to_string(),
            "ip -d -json addr show" => "[]".into(),
            "ip -json route show table main" => main_table().to_string(),
            "ip -json route show table 4242" | "ip -json rule show" => "[]".into(),
            l if l.starts_with("vtysh") && l.contains("show running-config") => String::new(),
            l if l.starts_with("vtysh") && l.contains("route babel json") => "{}".into(),
            l if l.starts_with("vtysh") => String::new(),
            l if l.starts_with("ip ") => String::new(),
            _ => return Err(Error::Backend(format!("unexpected {line}"))),
        })
    }
}

#[tokio::test]
async fn a_vpc_member_tunnels_to_its_relays_and_meshes_only_over_them() {
    let store = Arc::new(FakeStore::default());
    *store.clock.lock().unwrap() = 10_000;
    for (e, _) in fleet() {
        store.add(&e, 9_990);
    }
    let own = entry("i-a3", "vpc-a", "10.1.0.13", 300);
    let overlay = Overlay::new(overlay_options(), own, vec!["10.1.0.0/16".parse().unwrap()], Some(store.clone())).await.unwrap();
    assert_eq!(overlay.own.since, 300, "seniority comes from the existing registry entry");
    let host = Arc::new(Host { calls: Mutex::new(vec![]), fresh: false });
    let options = Options {
        filter: Filter::default(),
        policy: Policy::default(),
        socket_dir: None,
        interval: 1.0,
        listen: "127.0.0.1".parse().unwrap(),
        port: 0,
        state_dir: std::env::temp_dir(),
        apply: true,
        overlay: Some(overlay_options()),
    };
    let mesh = Mesh::new(options, host.clone()).with_overlay(overlay);
    let _ = mesh.pass(&mut None).await;
    let calls = host.calls.lock().unwrap().clone();
    for relay in ["i-a1", "i-a2"] {
        let name = tunnel::tunnel_name(relay);
        assert!(calls.iter().any(|c| c.starts_with(&format!("ip link add {name} type gre local 10.1.0.13"))), "{calls:#?}");
    }
    let created: Vec<&String> = calls.iter().filter(|c| c.starts_with("ip link add")).collect();
    assert_eq!(created.len(), 2, "members never tunnel off-site: {created:?}");
    let rule = calls.iter().position(|c| c.starts_with("ip rule add")).unwrap();
    let first_tunnel = calls.iter().position(|c| c.starts_with("ip link add")).unwrap();
    assert!(rule < first_tunnel, "endpoints are pinned before tunnels exist");
    assert!(calls.iter().any(|c| c == "ip route replace 10.1.0.11/32 dev ens5 table 4242 proto 249"));
    // Babel runs only on the tunnel NIC (ens5 is withheld), and as a member this host advertises nothing.
    let configure = calls.iter().find(|c| c.starts_with("vtysh") && c.contains("configure terminal")).unwrap();
    assert!(configure.contains(&format!("network {}", tunnel::tunnel_name("i-b1"))));
    assert!(!configure.contains("network ens5"));
    assert!(configure.contains("RDM-OUT-V4-A seq 5 deny any"));
    assert!(configure.contains("RDM-IN-V4-A seq 5 deny 10.1.0.0/16 le 32"));
    assert_eq!(*store.puts.lock().unwrap(), 1);
}

const PEERS: &str = r#"[
  {"host": "a1", "endpoint": "10.1.0.11", "site": "vpc-a"},
  {"host": "a2", "endpoint": "10.1.0.12", "site": "vpc-a"},
  {"host": "a3", "endpoint": "10.1.0.13", "site": "vpc-a", "name": "app-3"},
  {"host": "b1", "endpoint": "10.2.0.11", "site": "vpc-b"},
  {"host": "m1", "endpoint": "192.168.50.5"}
]"#;

#[test]
fn peers_file_order_is_seniority_and_sites_default_to_the_host() {
    let entries = peers::parse(PEERS).unwrap();
    assert_eq!(hosts(&entries), ["a1", "a2", "a3", "b1", "m1"]);
    assert_eq!(entries.iter().map(|e| e.since).collect::<Vec<_>>(), [0, 1, 2, 3, 4]);
    assert_eq!(entries[4].site, "m1");
    assert_eq!((entries[0].name.as_str(), entries[2].name.as_str()), ("a1", "app-3"));

    let twice = r#"[{"host": "a1", "endpoint": "10.1.0.11"}, {"host": "a1", "endpoint": "10.1.0.12"}]"#;
    assert!(peers::parse(twice).unwrap_err().to_string().contains("listed twice"));
    let shared = r#"[{"host": "a1", "endpoint": "10.1.0.11"}, {"host": "a2", "endpoint": "10.1.0.11"}]"#;
    assert!(peers::parse(shared).unwrap_err().to_string().contains("10.1.0.11 is listed twice"));
    // A typo is an error, not a silently missing field.
    assert!(peers::parse(r#"[{"host": "a1", "endpiont": "10.1.0.11"}]"#).is_err());
}

#[test]
fn a_host_finds_itself_in_the_peers_file_by_endpoint() {
    let discovered = entry("i-0abc", "vpc-0123", "10.1.0.13", 1_700_000_000);
    let (own, entries) = peers::resolve(&discovered, peers::parse(PEERS).unwrap()).unwrap();
    assert_eq!((own.host.as_str(), own.site.as_str(), own.since), ("a3", "vpc-a", 2));
    assert_eq!(own.platform, Platform::Ec2, "the platform is discovered, not listed");
    assert!(entries.iter().all(|(_, age)| *age == 0));
    let selection = select(&own, &entries, 300, 2);
    assert_eq!(selection.relays["vpc-a"], ["a1", "a2"]);
    assert_eq!(hosts(&selection.peers), ["a1", "a2"]);

    let stranger = entry("i-0def", "vpc-0123", "10.1.0.99", 0);
    assert!(peers::resolve(&stranger, peers::parse(PEERS).unwrap()).unwrap_err().to_string().contains("10.1.0.99 is not listed"));
}

#[tokio::test]
async fn a_peers_file_host_tunnels_without_a_registry() {
    let path = std::env::temp_dir().join(format!("rd-peers-{}.json", std::process::id()));
    std::fs::write(&path, PEERS).unwrap();
    let mut options = overlay_options();
    options.source = overlay::Source::File(path.clone());
    let discovered = entry("i-0abc", "vpc-0123", "10.1.0.13", 0);
    let overlay = Overlay::new(options.clone(), discovered, vec!["10.1.0.0/16".parse().unwrap()], None).await.unwrap();
    let host = Host { calls: Mutex::new(vec![]), fresh: true };
    let (shape, errors) = overlay.reconcile(&host, true).await.unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(errors.is_empty(), "{errors:?}");
    assert!(!shape.relay);
    let calls = host.calls.lock().unwrap().clone();
    let created: Vec<&String> = calls.iter().filter(|c| c.starts_with("ip link add")).collect();
    assert_eq!(created.len(), 2, "{created:?}");
    for relay in ["a1", "a2"] {
        assert!(created.iter().any(|c| c.starts_with(&format!("ip link add {} ", tunnel::tunnel_name(relay)))));
    }
    // Tunnel addresses come from the listed ID, which every peer agrees on.
    let ll = format!("ip addr add {}/64", tunnel::link_local("a3"));
    assert!(calls.iter().any(|c| c.starts_with(&ll)), "{calls:#?}");
    assert_eq!(overlay.snapshot()["host"]["host"], "a3");
    // On a fresh host table 4242 doesn't exist yet; the pass still pins endpoints, which creates it.
    assert!(calls.iter().any(|c| c == "ip route replace 10.1.0.11/32 dev ens5 table 4242 proto 249"), "{calls:#?}");
}
