use std::sync::{Arc, Mutex};

use route_discovery::commands::Runner;
use route_discovery::error::{Error, Result};
use route_discovery::mesh::frr::{desired, parse_routes, parse_running, plan, render, withdraw_plan, Desired, Policy};
use route_discovery::mesh::inventory::{glob, parse, Filter, Inventory, Medium};
use route_discovery::mesh::{Mesh, Options};
use serde_json::{json, Value};

fn link(name: &str, flags: &[&str], addresses: &[(&str, u8)]) -> Value {
    let info: Vec<Value> = addresses.iter().map(|(a, l)| json!({"local": a, "prefixlen": l})).collect();
    json!({"ifname": name, "flags": flags, "operstate": "UP", "addr_info": info})
}

const UP: &[&str] = &["BROADCAST", "MULTICAST", "UP", "LOWER_UP"];

fn host() -> Value {
    let mut slave = link("eth9", UP, &[("fe80::9", 64)]);
    slave["master"] = json!("bond0");
    json!([
        link("lo", &["LOOPBACK", "UP"], &[("127.0.0.1", 8), ("::1", 128)]),
        link("eth0", UP, &[("10.1.0.5", 24), ("fe80::1", 64), ("2001:db8:1::5", 64)]),
        link("wlan0", UP, &[("192.168.7.2", 24), ("fe80::2", 64)]),
        link("docker0", UP, &[("172.17.0.1", 16), ("fe80::3", 64)]),
        link("wg0", &["POINTOPOINT", "NOARP", "UP"], &[("10.9.0.1", 24)]),
        link("eth1", &["BROADCAST", "MULTICAST"], &[("10.2.0.5", 24), ("fe80::4", 64)]),
        link("ipsec0", UP, &[("169.254.1.2", 30), ("fe80::5", 64)]),
        slave,
    ])
}

fn inventory() -> Inventory {
    parse(&host(), &Filter::default(), &|name| name == "wlan0").unwrap()
}

#[test]
fn globs() {
    assert!(glob("br-*", "br-1234"));
    assert!(glob("*.calico", "vxlan.calico"));
    assert!(glob("a*b*c", "aXbYc"));
    assert!(!glob("a*b*c", "aXcYb"));
    assert!(!glob("eth0", "eth01"));
    assert!(!glob("ab*ba", "aba"));
}

#[test]
fn inventory_publishes_only_reachable_nics() {
    let inv = inventory();
    let names: Vec<&str> = inv.nics.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, ["eth0", "ipsec0", "wlan0"]);
    assert_eq!(inv.nics[0].prefixes.iter().map(ToString::to_string).collect::<Vec<_>>(), ["10.1.0.0/24", "2001:db8:1::/64"]);
    // Link-local tunnel addressing carries Babel but is never published.
    assert!(inv.nics[1].prefixes.is_empty());
    assert_eq!(inv.nics[2].medium, Medium::Wireless);
    let reason = |n: &str| inv.skipped.iter().find(|s| s.name == n).unwrap().reason.clone();
    assert!(reason("docker0").contains("docker*"));
    assert!(reason("wg0").contains("MULTICAST"));
    assert!(reason("eth1").contains("down"));
    assert!(reason("eth9").contains("bond0"));
    assert_eq!(inv.withheld.iter().map(ToString::to_string).collect::<Vec<_>>(), ["10.2.0.0/24", "10.9.0.0/24", "172.17.0.0/16"]);
}

#[test]
fn include_overrides_default_exclusions() {
    let filter = Filter { include: vec!["docker*".into()], exclude: vec![] };
    let inv = parse(&host(), &filter, &|_| false).unwrap();
    assert_eq!(inv.nics.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), ["docker0"]);
    assert!(parse(&json!([{"flags": []}]), &filter, &|_| false).is_err());
}

#[test]
fn out_filter_denies_withheld_before_relaying_supernets() {
    let want = desired(&inventory(), &Policy::default());
    let out = &want.filters[&(route_discovery::mesh::frr::Direction::Out, 4)];
    let position = |entry: &str| out.iter().position(|e| e == entry).unwrap_or_else(|| panic!("{entry}"));
    assert!(position("deny 172.17.0.0/16") < position("permit 172.16.0.0/12 le 32"));
    assert!(position("permit 10.1.0.0/24") < position("permit 10.0.0.0/8 le 32"));
    assert_eq!(out.last().unwrap(), "deny any");
    let text = render(&want);
    for fragment in
        ["network eth0", "network wlan0", " babel wireless", "babel hello-interval 1000", "redistribute ipv6 connected"]
    {
        assert!(text.contains(fragment), "{fragment}");
    }
    assert!(!text.contains("network docker0"));
}

#[test]
fn rendered_config_round_trips_as_converged() {
    let want = desired(&inventory(), &Policy::default());
    assert!(plan(&want, &parse_running(&render(&want))).is_empty());
}

#[test]
fn fresh_frr_creates_everything_before_switching_filters() {
    let want = desired(&inventory(), &Policy::default());
    let commands = plan(&want, &parse_running(""));
    let router = commands.iter().position(|c| c == "router babel").unwrap();
    let first_filter = commands.iter().position(|c| c.contains("distribute-list")).unwrap();
    let last_list = commands.iter().rposition(|c| c.contains("prefix-list RDM-") && c.contains(" seq ")).unwrap();
    assert!(last_list < router && router < first_filter);
    assert!(commands.contains(&"network eth0".to_string()));
    assert!(commands.contains(&"distribute-list prefix RDM-OUT-V4-A out".to_string()));
}

#[test]
fn changed_inventory_switches_generation_and_retires_old() {
    let before = desired(&inventory(), &Policy::default());
    let running = parse_running(&render(&before));
    let mut data = host();
    data.as_array_mut().unwrap().retain(|l| l["ifname"] != "wlan0");
    let after = desired(&parse(&data, &Filter::default(), &|_| false).unwrap(), &Policy::default());
    let commands = plan(&after, &running);
    assert!(commands.contains(&"no network wlan0".to_string()));
    assert!(commands.contains(&"distribute-list prefix RDM-OUT-V4-B out".to_string()));
    assert_eq!(commands.last().unwrap(), "no ip prefix-list RDM-OUT-V4-A");
    // Inbound filters are unchanged, so they are not rewritten.
    assert!(!commands.iter().any(|c| c.contains("RDM-IN-")));
    assert!(!commands.iter().any(|c| c.contains("RDM-OUT-V6")));
}

#[test]
fn foreign_networks_removed_and_orphans_retired() {
    let want = desired(&inventory(), &Policy::default());
    let text = render(&want) + "ip prefix-list RDM-OUT-V4-B seq 5 deny any\nrouter babel\n network eth7\nexit\n";
    let commands = plan(&want, &parse_running(&text));
    assert_eq!(commands.iter().filter(|c| c.starts_with("network ") || c.starts_with("no network")).count(), 1);
    assert!(commands.contains(&"no network eth7".to_string()));
    assert!(commands.contains(&"no ip prefix-list RDM-OUT-V4-B".to_string()));
}

#[test]
fn withdraw_removes_owned_state() {
    let running = parse_running(&render(&desired(&inventory(), &Policy::default())));
    let commands = withdraw_plan(&running);
    assert_eq!(commands[0], "no router babel");
    assert_eq!(commands.len(), 5);
    assert!(withdraw_plan(&parse_running("")).is_empty());
}

#[test]
fn babel_routes_from_zebra_json() {
    let data = json!({
        "10.3.0.0/24": [{"selected": true, "nexthops": [
            {"ip": "fe80::7", "interfaceName": "eth0", "active": true},
            {"ip": "fe80::8", "interfaceName": "wlan0", "active": false}]}],
        "10.4.0.0/24": [{"selected": false, "nexthops": []}]
    });
    let routes = parse_routes(&data).unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].next_hops, ["fe80::7 dev eth0"]);
    assert!(parse_routes(&json!([])).is_err());
}

/// vtysh/ip double: `running` is what FRR reports; configure calls are recorded but not absorbed.
struct Fake {
    running: Mutex<String>,
    configures: Mutex<usize>,
}

#[async_trait::async_trait]
impl Runner for Fake {
    async fn run(&self, args: &[String], _timeout: f64) -> Result<String> {
        match args[0].as_str() {
            "ip" => Ok(host().to_string()),
            "vtysh" if args.iter().any(|a| a == "configure terminal") => {
                *self.configures.lock().unwrap() += 1;
                Ok(String::new())
            }
            "vtysh" if args.last().unwrap().starts_with("show running-config") => Ok(self.running.lock().unwrap().clone()),
            _ => Err(Error::Backend("unexpected".into())),
        }
    }
}

fn mesh(running: String, apply: bool) -> (Mesh, Arc<Fake>) {
    let fake = Arc::new(Fake { running: Mutex::new(running), configures: Mutex::new(0) });
    let options = Options {
        filter: Filter::default(),
        policy: Policy::default(),
        socket_dir: None,
        interval: 1.0,
        listen: "127.0.0.1".parse().unwrap(),
        port: 0,
        state_dir: std::env::temp_dir(),
        apply,
        overlay: None,
    };
    (Mesh::new(options, fake.clone()), fake)
}

fn sysfs_free_desired() -> Desired {
    // The real collector probes /sys for wireless; the fake host has no wlan0 entry there.
    desired(&parse(&host(), &Filter::default(), &|_| false).unwrap(), &Policy::default())
}

#[tokio::test]
async fn converged_pass_writes_nothing() {
    let (mesh, fake) = mesh(render(&sysfs_free_desired()), true);
    assert!(mesh.pass(&mut None).await.unwrap());
    assert_eq!(*fake.configures.lock().unwrap(), 0);
}

#[tokio::test]
async fn unabsorbed_plan_is_not_replayed() {
    let (mesh, fake) = mesh(String::new(), true);
    let mut stuck = None;
    assert!(!mesh.pass(&mut stuck).await.unwrap());
    assert!(!mesh.pass(&mut stuck).await.unwrap());
    assert_eq!(*fake.configures.lock().unwrap(), 1);
    *fake.running.lock().unwrap() = render(&sysfs_free_desired());
    assert!(mesh.pass(&mut stuck).await.unwrap());
    assert!(stuck.is_none());
}

#[tokio::test]
async fn dry_run_never_configures() {
    let (mesh, fake) = mesh(String::new(), false);
    assert!(!mesh.pass(&mut None).await.unwrap());
    assert_eq!(*fake.configures.lock().unwrap(), 0);
}
