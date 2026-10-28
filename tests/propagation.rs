mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use common::{demo, source_data};
use route_discovery::aws::{Ec2, Ec2Route, NetworkInterface, RouteRequest, RouteTable};
use route_discovery::error::{backend_err, Result};
use route_discovery::server::config::{Propagation, ServerConfig};
use route_discovery::server::frr::parse_snapshot;
use route_discovery::server::journal::Journal;
use route_discovery::server::propagation::Propagator;
use route_discovery::server::rib::{Fib, LearnedRoute};

type Hook = Box<dyn Fn(&RouteRequest) + Send + Sync>;

#[derive(Default)]
struct State {
    tables: BTreeMap<String, RouteTable>,
    interfaces: Vec<NetworkInterface>,
    calls: Vec<(&'static str, RouteRequest)>,
    fail_table: Option<String>,
    lag: bool,
}

#[derive(Default)]
struct FakeEc2 {
    state: Mutex<State>,
    before_create: Mutex<Option<Hook>>,
}

impl FakeEc2 {
    fn new(config: &ServerConfig) -> Arc<Self> {
        let fake = FakeEc2::default();
        {
            let mut state = fake.state.lock().unwrap();
            for p in &config.propagations {
                let table = RouteTable {
                    id: p.table.clone(),
                    vpc_id: Some(config.vpc_id.clone()),
                    tags: [(config.owner_tag.clone(), config.id.clone())].into(),
                    ..Default::default()
                };
                state.tables.insert(p.table.clone(), table);
            }
            state.interfaces = config
                .peers
                .iter()
                .map(|p| NetworkInterface {
                    id: p.eni.clone(),
                    vpc_id: Some(config.vpc_id.clone()),
                    status: Some("in-use".into()),
                    source_dest_check: Some(false),
                    addresses: vec![p.next_hops[0].clone()],
                })
                .collect();
        }
        Arc::new(fake)
    }

    fn mutate(&self, operation: &'static str, request: &RouteRequest) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.calls.push((operation, request.clone()));
        if state.fail_table.as_deref() == Some(request.table_id.as_str()) {
            return backend_err("AWS throttling");
        }
        if !state.lag {
            let table = state.tables.get_mut(&request.table_id).unwrap();
            table.routes.retain(|r| r.destination() != Some(request.prefix.as_str()));
            if operation != "delete" {
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
                table.routes.push(route);
            }
        }
        Ok(())
    }

    fn operations(&self) -> Vec<&'static str> {
        self.state.lock().unwrap().calls.iter().map(|c| c.0).collect()
    }

    fn count(&self, operation: &str) -> usize {
        self.operations().iter().filter(|o| **o == operation).count()
    }
}

#[async_trait]
impl Ec2 for FakeEc2 {
    async fn describe_route_tables(&self, ids: &[String]) -> Result<Vec<RouteTable>> {
        let state = self.state.lock().unwrap();
        Ok(ids.iter().filter_map(|id| state.tables.get(id).cloned()).collect())
    }

    async fn describe_network_interfaces(&self, _ids: &[String]) -> Result<Vec<NetworkInterface>> {
        Ok(self.state.lock().unwrap().interfaces.clone())
    }

    async fn create_route(&self, request: &RouteRequest) -> Result<()> {
        if let Some(hook) = &*self.before_create.lock().unwrap() {
            hook(request);
        }
        self.mutate("create", request)
    }

    async fn replace_route(&self, request: &RouteRequest) -> Result<()> {
        self.mutate("replace", request)
    }

    async fn delete_route(&self, request: &RouteRequest) -> Result<()> {
        self.mutate("delete", request)
    }
}

struct Fixture {
    config: ServerConfig,
    journal: Arc<Mutex<Journal>>,
    ec2: Arc<FakeEc2>,
    backend: Propagator,
    a: LearnedRoute,
    b: LearnedRoute,
}

impl Fixture {
    fn new() -> Self {
        Self::with_journal(None)
    }

    fn with_journal(directory: Option<&std::path::Path>) -> Self {
        let config = demo();
        let journal = Arc::new(Mutex::new(Journal::open(&config, directory).unwrap()));
        let ec2 = FakeEc2::new(&config);
        let backend = Propagator::new(config.clone(), journal.clone(), Some(ec2.clone()), true).unwrap();
        let routes = parse_snapshot(&config, &config.endpoints[0], &source_data(&config)).unwrap().routes;
        Fixture { config, journal, ec2, backend, a: routes[0].clone(), b: routes[1].clone() }
    }

    async fn reconcile(&self, routes: &[&LearnedRoute]) -> bool {
        let fib: Fib = routes.iter().map(|r| (r.prefix.clone(), (*r).clone())).collect();
        self.backend.reconcile(&fib, &|| true).await.unwrap()
    }

    fn table_status(&self, index: usize) -> route_discovery::server::propagation::TableState {
        self.backend.status.lock().unwrap()[&self.config.propagations[index].table].clone()
    }

    fn entries(&self) -> BTreeMap<(String, String), BTreeSet<String>> {
        self.journal.lock().unwrap().entries().unwrap()
    }

    fn table(&self, index: usize) -> String {
        self.config.propagations[index].table.clone()
    }
}

#[tokio::test]
async fn multi_table_learning_failover_and_withdrawal() {
    let t = Fixture::new();
    for route in [&t.a, &t.b, &t.a] {
        assert!(t.reconcile(&[route]).await);
    }
    assert!(t.reconcile(&[]).await);
    assert_eq!((t.ec2.count("create"), t.ec2.count("replace"), t.ec2.count("delete")), (2, 4, 2));
    assert!(t.entries().is_empty());
}

#[tokio::test]
async fn does_not_adopt_unowned_route_even_with_same_target() {
    let t = Fixture::new();
    let table = t.table(0);
    let request = RouteRequest {
        table_id: table.clone(),
        prefix: t.a.prefix.clone(),
        ipv6: false,
        network_interface_id: Some(t.a.eni.clone()),
    };
    t.ec2.mutate("create", &request).unwrap();
    t.ec2.state.lock().unwrap().calls.clear();
    assert!(!t.reconcile(&[&t.a]).await);
    assert!(!t.entries().contains_key(&(table, t.a.prefix.clone())));
    assert!(t.table_status(1).converged);
}

#[tokio::test]
async fn intent_is_durable_before_api_write() {
    let directory = tempfile::tempdir().unwrap();
    let t = Fixture::with_journal(Some(directory.path()));
    let path = directory.path().join("route-server.sqlite3");
    let checked = Arc::new(Mutex::new(0));
    let seen = checked.clone();
    *t.ec2.before_create.lock().unwrap() = Some(Box::new(move |request| {
        let reader = rusqlite::Connection::open(&path).unwrap();
        let targets: String = reader
            .query_row("SELECT targets FROM routes WHERE table_id=? AND prefix=?", [&request.table_id, &request.prefix], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(targets.contains(request.network_interface_id.as_deref().unwrap()));
        *seen.lock().unwrap() += 1;
    }));
    assert!(t.reconcile(&[&t.a]).await);
    assert_eq!(*checked.lock().unwrap(), 2);
}

#[tokio::test]
async fn partial_failure_does_not_block_other_table() {
    let t = Fixture::new();
    t.ec2.state.lock().unwrap().fail_table = Some(t.table(0));
    assert!(!t.reconcile(&[&t.a]).await);
    assert!(t.table_status(1).converged);
    t.ec2.state.lock().unwrap().fail_table = None;
    assert!(t.reconcile(&[&t.a]).await);
}

#[tokio::test]
async fn eventual_consistency_and_delayed_deletion() {
    let t = Fixture::new();
    let lag = |on: bool| t.ec2.state.lock().unwrap().lag = on;
    lag(true);
    assert!(!t.reconcile(&[&t.a]).await);
    lag(false);
    assert!(t.reconcile(&[&t.a]).await);
    lag(true);
    assert!(!t.reconcile(&[]).await);
    assert!(!t.entries().is_empty());
    lag(false);
    assert!(t.reconcile(&[]).await);
    assert!(t.entries().is_empty());
}

#[tokio::test]
async fn missing_tag_wrong_vpc_and_local_route_are_protected() {
    let t = Fixture::new();
    let table = t.table(0);
    let edit = |f: &dyn Fn(&mut RouteTable)| f(t.ec2.state.lock().unwrap().tables.get_mut(&table).unwrap());
    edit(&|tb| tb.tags.clear());
    assert!(!t.reconcile(&[&t.a]).await);
    assert!(t.table_status(0).error.unwrap().contains("ownership tag"));
    edit(&|tb| {
        tb.tags = [(t.config.owner_tag.clone(), t.config.id.clone())].into();
        tb.vpc_id = Some("vpc-fffffffffffffffff".into());
    });
    assert!(!t.reconcile(&[&t.a]).await);
    edit(&|tb| {
        tb.vpc_id = Some(t.config.vpc_id.clone());
        tb.routes = vec![Ec2Route {
            destination_cidr: Some(t.a.prefix.clone()),
            origin: Some("CreateRouteTable".into()),
            gateway_id: Some("local".into()),
            ..Default::default()
        }];
    });
    assert!(!t.reconcile(&[&t.a]).await);
    assert!(t.table_status(0).routes[&t.a.prefix].error.as_ref().unwrap().contains("journal-owned"));
}

#[tokio::test]
async fn eni_mapping_and_source_destination_checks() {
    let t = Fixture::new();
    let fib: Fib = [(t.a.prefix.clone(), t.a.clone())].into();
    t.ec2.state.lock().unwrap().interfaces[0].source_dest_check = Some(true);
    assert!(t.backend.reconcile(&fib, &|| true).await.is_err());
    {
        let mut state = t.ec2.state.lock().unwrap();
        state.interfaces[0].source_dest_check = Some(false);
        state.interfaces[0].addresses.clear();
    }
    assert!(t.backend.reconcile(&fib, &|| true).await.is_err());
}

#[tokio::test]
async fn removed_or_disabled_propagation_cleans_owned_routes() {
    let mut t = Fixture::new();
    t.reconcile(&[&t.a]).await;
    let first = t.table(0);
    t.backend.config.propagations = vec![t.config.propagations[1].clone()];
    assert!(t.reconcile(&[&t.a]).await);
    assert!(t.ec2.state.lock().unwrap().tables[&first].routes.is_empty());
    t.backend.config.propagations = t.config.propagations.iter().map(|p| Propagation { enabled: false, ..p.clone() }).collect();
    assert!(t.reconcile(&[&t.a]).await);
    assert!(t.entries().is_empty());
}

#[tokio::test]
async fn prefix_filter_and_ipv6_api_field() {
    let mut t = Fixture::new();
    t.backend.config.propagations =
        vec![Propagation { allowed_prefixes: vec!["2001:db8::/32".into()], ..t.config.propagations[0].clone() }];
    let route6 = LearnedRoute { prefix: "2001:db8:20::/64".into(), ..t.a.clone() };
    assert!(t.reconcile(&[&t.a, &route6]).await);
    let calls = t.ec2.state.lock().unwrap().calls.clone();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].1.ipv6);
}

#[tokio::test]
async fn generation_guard_prevents_obsolete_writes() {
    let t = Fixture::new();
    let fib: Fib = [(t.a.prefix.clone(), t.a.clone())].into();
    assert!(!t.backend.reconcile(&fib, &|| false).await.unwrap());
    assert!(t.ec2.operations().is_empty());
}

#[tokio::test]
async fn unexpected_target_after_restart_is_not_overwritten() {
    let t = Fixture::new();
    t.reconcile(&[&t.a]).await;
    for table in t.ec2.state.lock().unwrap().tables.values_mut() {
        table.routes[0].network_interface_id = Some("eni-fffffffffffffffff".into());
    }
    assert!(!t.reconcile(&[&t.b]).await);
    assert!(!t.reconcile(&[]).await);
}

#[tokio::test]
async fn dry_run_never_reads_aws() {
    let t = Fixture::new();
    let backend = Propagator::new(t.config.clone(), t.journal.clone(), Some(t.ec2.clone()), false).unwrap();
    let fib: Fib = [(t.a.prefix.clone(), t.a.clone())].into();
    assert!(backend.reconcile(&fib, &|| true).await.unwrap());
    assert_eq!(backend.simulated.lock().unwrap().len(), 2);
    assert!(t.ec2.operations().is_empty());
}

#[tokio::test]
async fn maximum_route_count_holds_table() {
    let mut t = Fixture::new();
    t.backend.config.propagations = t.config.propagations.iter().map(|p| Propagation { max_routes: 1, ..p.clone() }).collect();
    let extra = LearnedRoute { prefix: "10.20.2.0/24".into(), ..t.a.clone() };
    assert!(!t.reconcile(&[&t.a, &extra]).await);
    assert!(t.ec2.operations().is_empty());
}
