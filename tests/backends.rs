mod common;

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use common::{configuration, linux};
use route_discovery::aws::{Ec2, Ec2Route, NetworkInterface, RouteRequest, RouteTable};
use route_discovery::backends::{validate_probe_paths, Aws, Backend, Frr, Linux, Observed};
use route_discovery::commands::Runner;
use route_discovery::config::{BackendKind, Route};
use route_discovery::error::{backend_err, Error, Result};
use route_discovery::policy::{Action, Decision};
use serde_json::{json, Value};

fn withdraw() -> Decision {
    Decision::new(Action::Withdraw, "")
}

/// Simulates `ip -j route` for one prefix, recording every command.
#[derive(Default)]
struct FakeIp {
    records: Mutex<Value>,
    commands: Mutex<Vec<Vec<String>>>,
}

#[async_trait]
impl Runner for FakeIp {
    async fn run(&self, args: &[String], _timeout: f64) -> Result<String> {
        self.commands.lock().unwrap().push(args.to_vec());
        let has = |word: &str| args.iter().any(|a| a == word);
        let mut records = self.records.lock().unwrap();
        if has("show") {
            return Ok(if records.is_null() { "[]".into() } else { records.to_string() });
        }
        *records = if has("del") {
            json!([])
        } else if has("unreachable") {
            json!([{"type": "unreachable", "protocol": 196, "metric": 100}])
        } else {
            let hops: Vec<Value> = args.windows(2).filter(|w| w[0] == "dev").map(|w| json!({"dev": w[1]})).collect();
            json!([{"protocol": 196, "metric": 100, "nexthops": hops}])
        };
        Ok(String::new())
    }
}

fn linux_backend() -> (Arc<FakeIp>, Linux, Route) {
    let config = linux();
    let fake = Arc::new(FakeIp::default());
    (fake.clone(), Linux::new(&config, fake), config.routes[0].clone())
}

fn writes(fake: &FakeIp, verb: &str) -> Vec<Vec<String>> {
    fake.commands.lock().unwrap().iter().filter(|c| c.iter().any(|a| a == verb)).cloned().collect()
}

#[tokio::test]
async fn linux_atomic_replace_and_withdraw() {
    let (fake, backend, route) = linux_backend();
    assert!(backend.apply(&route, &Decision::route(&["primary"])).await.unwrap());
    assert!(backend.apply(&route, &Decision::route(&["backup"])).await.unwrap());
    let changes = writes(&fake, "replace");
    assert_eq!(changes.len(), 2);
    assert!(changes[1].contains(&"wg-b".to_string()));
    assert!(backend.apply(&route, &withdraw()).await.unwrap());
}

#[tokio::test]
async fn linux_idempotent_and_unreachable() {
    let (fake, backend, route) = linux_backend();
    let decision = Decision::route(&["primary"]);
    backend.apply(&route, &decision).await.unwrap();
    backend.apply(&route, &decision).await.unwrap();
    assert_eq!(writes(&fake, "replace").len(), 1);
    backend.apply(&route, &Decision::new(Action::Unreachable, "")).await.unwrap();
    assert_eq!(backend.current(&route).await.unwrap(), Observed::unreachable());
}

#[tokio::test]
async fn linux_refuses_foreign_routes() {
    let (fake, backend, route) = linux_backend();
    for record in [
        json!({"protocol": "static", "metric": 100, "dev": "wg-a"}),
        json!({"protocol": 196, "metric": 20, "dev": "wg-a"}),
        json!({"protocol": 196, "metric": 100, "dev": "eth9"}),
    ] {
        *fake.records.lock().unwrap() = json!([record]);
        assert!(matches!(backend.apply(&route, &withdraw()).await, Err(Error::Backend(_))));
    }
}

#[tokio::test]
async fn linux_ecmp_replace_contains_all_next_hops() {
    let (fake, backend, route) = linux_backend();
    assert!(backend.apply(&route, &Decision::route(&["backup", "primary"])).await.unwrap());
    let command = &writes(&fake, "replace")[0];
    assert_eq!(command.iter().filter(|a| *a == "nexthop").count(), 2);
}

#[tokio::test]
async fn linux_ipv6_route_family() {
    let (fake, backend, mut route) = linux_backend();
    route.prefix = "2001:db8::/64".parse().unwrap();
    backend.apply(&route, &Decision::route(&["primary"])).await.unwrap();
    assert!(fake.commands.lock().unwrap().iter().all(|c| c.contains(&"-6".to_string())));
}

#[tokio::test]
async fn linux_write_failure_is_propagated() {
    let config = linux();
    let fail = |args: &[String]| -> Result<String> {
        if args.iter().any(|a| a == "show") {
            Ok("[]".into())
        } else {
            backend_err("permission denied")
        }
    };
    let backend = Linux::new(&config, Arc::new(fail));
    assert!(backend.apply(&config.routes[0], &Decision::route(&["primary"])).await.is_err());
}

#[tokio::test]
async fn probe_drift_is_rejected() {
    let wrong = |_: &[String]| -> Result<String> { Ok(json!([{"table": 254, "dev": "wg-b"}]).to_string()) };
    assert!(validate_probe_paths(&linux(), &wrong).await.is_err());
}

#[tokio::test]
async fn probe_correct_path_requires_terminal_route() {
    let right = |args: &[String]| -> Result<String> {
        let after = |word: &str| args.iter().position(|a| a == word).map(|i| args[i + 1].clone());
        if args.iter().any(|a| a == "get") {
            Ok(json!([{"table": after("mark"), "dev": after("oif")}]).to_string())
        } else {
            Ok(json!([{"type": "7"}]).to_string())
        }
    };
    validate_probe_paths(&linux(), &right).await.unwrap();
    let missing_terminal = |args: &[String]| -> Result<String> {
        if args.iter().any(|a| a == "get") {
            right(args)
        } else {
            Ok("[]".into())
        }
    };
    assert!(validate_probe_paths(&linux(), &missing_terminal).await.is_err());
}

#[tokio::test]
async fn numeric_unreachable_route_type() {
    let (fake, backend, route) = linux_backend();
    *fake.records.lock().unwrap() = json!([{"type": "7", "protocol": "196", "metric": 100}]);
    assert_eq!(backend.current(&route).await.unwrap(), Observed::unreachable());
}

#[derive(Default)]
struct FakeEc2State {
    routes: Vec<Ec2Route>,
    tags: HashMap<String, String>,
    calls: Vec<(&'static str, RouteRequest)>,
    fail: bool,
    lag: bool,
}

#[derive(Default)]
struct FakeEc2(Mutex<FakeEc2State>);

impl FakeEc2 {
    fn new() -> Arc<Self> {
        let fake = FakeEc2::default();
        fake.0.lock().unwrap().tags.insert("route-discovery".into(), "managed".into());
        Arc::new(fake)
    }

    fn write(&self, operation: &'static str, request: &RouteRequest) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        state.calls.push((operation, request.clone()));
        if state.fail {
            return backend_err("Throttling");
        }
        if !state.lag {
            let mut route = Ec2Route {
                network_interface_id: request.network_interface_id.clone(),
                origin: Some("CreateRoute".into()),
                state: Some("active".into()),
                ..Default::default()
            };
            if request.ipv6 {
                route.destination_ipv6_cidr = Some(request.prefix.clone());
            } else {
                route.destination_cidr = Some(request.prefix.clone());
            }
            state.routes = vec![route];
        }
        Ok(())
    }

    fn operations(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().calls.iter().map(|c| c.0).collect()
    }
}

#[async_trait]
impl Ec2 for FakeEc2 {
    async fn describe_route_tables(&self, _ids: &[String]) -> Result<Vec<RouteTable>> {
        let state = self.0.lock().unwrap();
        Ok(vec![RouteTable {
            id: "rtb-0123456789abcdef0".into(),
            tags: state.tags.clone(),
            routes: state.routes.clone(),
            ..Default::default()
        }])
    }

    async fn describe_network_interfaces(&self, _ids: &[String]) -> Result<Vec<NetworkInterface>> {
        Ok(vec![])
    }

    async fn create_route(&self, request: &RouteRequest) -> Result<()> {
        self.write("create", request)
    }

    async fn replace_route(&self, request: &RouteRequest) -> Result<()> {
        self.write("replace", request)
    }

    async fn delete_route(&self, request: &RouteRequest) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(("delete", request.clone()));
        state.routes.clear();
        Ok(())
    }
}

fn aws_backend() -> (Arc<FakeEc2>, Aws, Route) {
    let config = configuration(BackendKind::Aws, |_| {});
    let ec2 = FakeEc2::new();
    (ec2.clone(), Aws::new(&config, ec2), config.routes[0].clone())
}

#[tokio::test]
async fn aws_create_failover_failback_delete() {
    let (ec2, backend, route) = aws_backend();
    for cid in ["primary", "backup", "primary"] {
        assert!(backend.apply(&route, &Decision::route(&[cid])).await.unwrap());
    }
    assert!(backend.apply(&route, &withdraw()).await.unwrap());
    assert_eq!(ec2.operations(), ["create", "replace", "replace", "delete"]);
}

#[tokio::test]
async fn aws_no_write_on_same_target() {
    let (ec2, backend, route) = aws_backend();
    let decision = Decision::route(&["primary"]);
    backend.apply(&route, &decision).await.unwrap();
    backend.apply(&route, &decision).await.unwrap();
    assert_eq!(ec2.operations().len(), 1);
}

#[tokio::test]
async fn aws_missing_ownership_tag_blocks_write() {
    let (ec2, backend, route) = aws_backend();
    ec2.0.lock().unwrap().tags.clear();
    assert!(backend.apply(&route, &Decision::route(&["primary"])).await.is_err());
    assert!(ec2.operations().is_empty());
}

#[tokio::test]
async fn aws_foreign_local_and_propagated_routes_are_protected() {
    let (ec2, backend, route) = aws_backend();
    let prefix = Some(route.key());
    for record in [
        Ec2Route { gateway_id: Some("local".into()), origin: Some("CreateRouteTable".into()), ..Default::default() },
        Ec2Route {
            network_interface_id: Some("eni-fffffffffffffffff".into()),
            origin: Some("CreateRoute".into()),
            ..Default::default()
        },
        Ec2Route {
            network_interface_id: route.candidates[0].aws_target.clone(),
            origin: Some("EnableVgwRoutePropagation".into()),
            ..Default::default()
        },
    ] {
        ec2.0.lock().unwrap().routes = vec![Ec2Route { destination_cidr: prefix.clone(), ..record }];
        assert!(backend.apply(&route, &withdraw()).await.is_err());
    }
}

#[tokio::test]
async fn aws_eventual_consistency_not_reported_as_success() {
    let (ec2, backend, route) = aws_backend();
    ec2.0.lock().unwrap().lag = true;
    assert!(!backend.apply(&route, &Decision::route(&["primary"])).await.unwrap());
}

#[tokio::test]
async fn aws_blackhole_not_treated_as_installed() {
    let (ec2, backend, route) = aws_backend();
    backend.apply(&route, &Decision::route(&["primary"])).await.unwrap();
    ec2.0.lock().unwrap().routes[0].state = Some("blackhole".into());
    assert!(!backend.current(&route).await.unwrap().usable);
    assert!(backend.apply(&route, &Decision::route(&["primary"])).await.unwrap());
    assert_eq!(*ec2.operations().last().unwrap(), "replace");
}

#[tokio::test]
async fn aws_ipv6_uses_correct_api_field() {
    let (ec2, backend, mut route) = aws_backend();
    route.prefix = "2001:db8::/64".parse().unwrap();
    backend.apply(&route, &Decision::route(&["primary"])).await.unwrap();
    assert!(ec2.0.lock().unwrap().calls.last().unwrap().1.ipv6);
}

#[tokio::test]
async fn aws_api_error_is_propagated() {
    let (ec2, backend, route) = aws_backend();
    ec2.0.lock().unwrap().fail = true;
    assert!(backend.apply(&route, &Decision::route(&["primary"])).await.is_err());
}

/// Simulates `vtysh` running-config for static routes.
#[derive(Default)]
struct FakeVtysh {
    lines: Mutex<BTreeSet<String>>,
    changes: Mutex<Vec<String>>,
}

#[async_trait]
impl Runner for FakeVtysh {
    async fn run(&self, args: &[String], _timeout: f64) -> Result<String> {
        let mut lines = self.lines.lock().unwrap();
        if args.iter().any(|a| a == "show running-config") {
            return Ok(lines.iter().cloned().collect::<Vec<_>>().join("\n"));
        }
        for command in args.windows(2).filter(|w| w[0] == "-c").map(|w| w[1].clone()) {
            self.changes.lock().unwrap().push(command.clone());
            if command.starts_with("ip route ") {
                lines.insert(command);
            } else if let Some(removed) = command.strip_prefix("no ") {
                lines.remove(removed);
            }
        }
        Ok(String::new())
    }
}

fn frr_backend() -> (Arc<FakeVtysh>, Frr, Route) {
    let config = configuration(BackendKind::Frr, |_| {});
    let fake = Arc::new(FakeVtysh::default());
    (fake.clone(), Frr::new(&config, fake), config.routes[0].clone())
}

#[tokio::test]
async fn frr_add_before_remove_and_withdraw() {
    let (fake, backend, route) = frr_backend();
    backend.apply(&route, &Decision::route(&["primary"])).await.unwrap();
    fake.changes.lock().unwrap().clear();
    backend.apply(&route, &Decision::route(&["backup"])).await.unwrap();
    let changes = fake.changes.lock().unwrap().clone();
    let add = changes.iter().position(|c| *c == backend.command(&route, &route.candidates[1])).unwrap();
    let remove = changes.iter().position(|c| *c == format!("no {}", backend.command(&route, &route.candidates[0]))).unwrap();
    assert!(add < remove);
    backend.apply(&route, &withdraw()).await.unwrap();
    assert!(fake.lines.lock().unwrap().is_empty());
}

#[tokio::test]
async fn frr_restart_adopts_existing_tagged_routes() {
    let (fake, backend, route) = frr_backend();
    fake.lines.lock().unwrap().insert(backend.command(&route, &route.candidates[1]));
    assert_eq!(backend.current(&route).await.unwrap().paths, ["backup"]);
}

#[tokio::test]
async fn frr_other_static_route_blocks_modification() {
    let (fake, backend, route) = frr_backend();
    fake.lines.lock().unwrap().insert(format!("ip route {} eth9", route.key()));
    assert!(backend.apply(&route, &Decision::route(&["primary"])).await.is_err());
}
