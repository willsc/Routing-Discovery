//! Propagate learned FIB routes into explicitly associated VPC route tables.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use super::config::{permits, version, ServerConfig};
use super::journal::Journal;
use super::rib::Fib;
use crate::aws::{Ec2, Ec2Route, RouteRequest};
use crate::error::{backend_err, Result};

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct RouteState {
    pub desired: Option<String>,
    pub converged: bool,
    pub error: Option<String>,
    pub observed: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct TableState {
    pub enabled: bool,
    pub converged: bool,
    pub routes: BTreeMap<String, RouteState>,
    pub error: Option<String>,
}

pub struct Propagator {
    pub config: ServerConfig,
    pub journal: Arc<Mutex<Journal>>,
    pub client: Option<Arc<dyn Ec2>>,
    pub apply: bool,
    /// Off only for `server withdraw`: retiring owned routes needs no peer ENI verification.
    pub verify: bool,
    pub simulated: Mutex<HashMap<String, BTreeMap<String, Ec2Route>>>,
    pub status: Mutex<BTreeMap<String, TableState>>,
    pub changes: AtomicU64,
    pub failures: AtomicU64,
}

fn owned(record: &Ec2Route, targets: &BTreeSet<String>) -> bool {
    record.is_static() && record.network_interface_id.as_ref().is_some_and(|eni| targets.contains(eni))
}

impl Propagator {
    /// `client` is required when `apply` is set; a dry run never reads or writes AWS.
    pub fn new(config: ServerConfig, journal: Arc<Mutex<Journal>>, client: Option<Arc<dyn Ec2>>, apply: bool) -> Result<Self> {
        if apply && client.is_none() {
            return backend_err("an EC2 client is required to apply VPC routes");
        }
        Ok(Propagator {
            config,
            journal,
            client: if apply { client } else { None },
            apply,
            verify: true,
            simulated: Mutex::new(HashMap::new()),
            status: Mutex::new(BTreeMap::new()),
            changes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        })
    }

    fn ec2(&self) -> &dyn Ec2 {
        self.client.as_deref().expect("apply mode has a client")
    }

    pub async fn verify_targets(&self) -> Result<()> {
        if !self.apply || !self.verify {
            return Ok(());
        }
        let ids: Vec<String> = self.config.peers.iter().map(|p| p.eni.clone()).collect::<BTreeSet<_>>().into_iter().collect();
        let interfaces = self.ec2().describe_network_interfaces(&ids).await?;
        for peer in &self.config.peers {
            let eni = interfaces.iter().find(|e| e.id == peer.eni);
            let Some(eni) =
                eni.filter(|e| e.vpc_id.as_deref() == Some(&self.config.vpc_id) && e.status.as_deref() == Some("in-use"))
            else {
                return backend_err(format!("{}: ENI must be attached in the associated VPC", peer.id));
            };
            if eni.source_dest_check != Some(false) {
                return backend_err(format!("{}: forwarding ENI must have source/destination checking disabled", peer.id));
            }
            if !peer.next_hops.iter().all(|h| eni.addresses.contains(h)) {
                return backend_err(format!("{}: configured next hops do not belong to its ENI", peer.id));
            }
        }
        Ok(())
    }

    async fn table(&self, table_id: &str) -> Result<BTreeMap<String, Ec2Route>> {
        if !self.apply {
            return Ok(self.simulated.lock().unwrap().entry(table_id.to_string()).or_default().clone());
        }
        let tables = self.ec2().describe_route_tables(&[table_id.to_string()]).await?;
        if tables.len() != 1 || tables[0].id != table_id {
            return backend_err(format!("route table {table_id} missing"));
        }
        let table = &tables[0];
        if table.vpc_id.as_deref() != Some(&self.config.vpc_id) {
            return backend_err(format!("{table_id}: route table is outside the associated VPC"));
        }
        if table.tags.get(&self.config.owner_tag) != Some(&self.config.id) {
            return backend_err(format!("{table_id}: missing ownership tag {}={}", self.config.owner_tag, self.config.id));
        }
        if table.association_gateway_ids.iter().any(|g| g.starts_with("vgw-")) {
            return backend_err("virtual-private-gateway route tables are not supported");
        }
        Ok(table.routes.iter().filter_map(|r| Some((r.destination()?.to_string(), r.clone()))).collect())
    }

    async fn mutate(&self, table_id: &str, prefix: &str, target: Option<&str>, before: Option<&Ec2Route>) -> Result<()> {
        if !self.apply {
            let mut simulated = self.simulated.lock().unwrap();
            let table = simulated.entry(table_id.to_string()).or_default();
            match target {
                None => {
                    table.remove(prefix);
                }
                Some(eni) => {
                    let route = Ec2Route {
                        origin: Some("CreateRoute".into()),
                        state: Some("active".into()),
                        network_interface_id: Some(eni.into()),
                        ..Default::default()
                    };
                    table.insert(prefix.to_string(), route);
                }
            }
            return Ok(());
        }
        let request = RouteRequest {
            table_id: table_id.into(),
            prefix: prefix.into(),
            ipv6: version(prefix) == 6,
            network_interface_id: target.map(str::to_string),
        };
        match (target, before) {
            (None, _) => self.ec2().delete_route(&request).await,
            (Some(_), None) => self.ec2().create_route(&request).await,
            (Some(_), Some(_)) => self.ec2().replace_route(&request).await,
        }
    }

    fn journal(&self) -> std::sync::MutexGuard<'_, Journal> {
        self.journal.lock().unwrap()
    }

    fn fail(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    async fn reconcile_prefix(
        &self,
        table_id: &str,
        prefix: &str,
        wanted: Option<&String>,
        before: Option<&Ec2Route>,
        owned_targets: Option<&BTreeSet<String>>,
    ) -> Result<()> {
        if before.is_some_and(|b| owned_targets.is_none_or(|t| !owned(b, t))) {
            return backend_err("route is not journal-owned; refusing to overwrite/delete it");
        }
        let correct = before.is_some_and(|b| b.network_interface_id.as_ref() == wanted && b.active());
        if let Some(target) = wanted.filter(|_| !correct) {
            // Write-ahead intent covers a crash after AWS succeeds but before readback.
            self.journal().intent(table_id, prefix, target)?;
            self.mutate(table_id, prefix, Some(target), before).await?;
            self.changes.fetch_add(1, Ordering::Relaxed);
        } else if wanted.is_none() && before.is_some() {
            self.mutate(table_id, prefix, None, before).await?;
            self.changes.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn reconcile_table(
        &self,
        table_id: &str,
        desired: &BTreeMap<String, String>,
        limit: Option<usize>,
        guard: &(dyn Fn() -> bool + Sync),
        state: &mut TableState,
    ) -> Result<()> {
        if limit.is_some_and(|max| desired.len() > max) {
            return backend_err(format!("{table_id}: FIB exceeds configured max_routes"));
        }
        let observed = self.table(table_id).await?;
        let entries = self.journal().entries()?;
        let prefixes: BTreeSet<&String> =
            desired.keys().chain(entries.keys().filter(|(t, _)| t == table_id).map(|(_, p)| p)).collect();
        for prefix in prefixes {
            if !guard() {
                return backend_err("learned-route generation changed; defer remaining writes");
            }
            let wanted = desired.get(prefix);
            let owned_targets = entries.get(&(table_id.to_string(), prefix.clone()));
            let result = self.reconcile_prefix(table_id, prefix, wanted, observed.get(prefix), owned_targets).await;
            if result.is_err() {
                self.fail();
            }
            state.routes.insert(
                prefix.clone(),
                RouteState {
                    desired: wanted.cloned(),
                    converged: false,
                    error: result.err().map(|e| e.to_string()),
                    observed: None,
                },
            );
        }
        // Verify independently of API return codes, including delayed deletions.
        let after = self.table(table_id).await?;
        for (prefix, result) in state.routes.iter_mut() {
            if result.error.is_some() {
                continue;
            }
            let current = after.get(prefix);
            match &result.desired {
                None => {
                    result.converged = current.is_none();
                    if current.is_none() {
                        self.journal().forget(table_id, prefix)?;
                    }
                }
                Some(desired) => {
                    let targets = self.journal().entries()?.remove(&(table_id.to_string(), prefix.clone())).unwrap_or_default();
                    result.converged = current
                        .is_some_and(|c| c.active() && c.network_interface_id.as_ref() == Some(desired) && owned(c, &targets));
                }
            }
            result.observed = current.and_then(|c| c.network_interface_id.clone());
        }
        state.converged = state.routes.values().all(|r| r.converged);
        Ok(())
    }

    /// One pass over every configured or journal-owned table. True when all tables converged.
    pub async fn reconcile(&self, fib: &Fib, guard: &(dyn Fn() -> bool + Sync)) -> Result<bool> {
        // Verify the mapping on every pass; do not keep routing to reassigned ENI addresses.
        self.verify_targets().await?;
        let propagation_map: BTreeMap<&str, _> = self.config.propagations.iter().map(|t| (t.table.as_str(), t)).collect();
        let journal_tables: BTreeSet<String> = self.journal().entries()?.into_keys().map(|(table, _)| table).collect();
        let tables: BTreeSet<String> = propagation_map.keys().map(|t| t.to_string()).chain(journal_tables).collect();
        for table_id in tables {
            let target = propagation_map.get(table_id.as_str()).filter(|t| t.enabled);
            let desired: BTreeMap<String, String> = fib
                .iter()
                .filter(|(prefix, _)| {
                    target.is_some_and(|t| t.allowed_prefixes.is_empty() || permits(prefix, &t.allowed_prefixes))
                })
                .map(|(prefix, route)| (prefix.clone(), route.eni.clone()))
                .collect();
            let mut state = TableState { enabled: target.is_some(), ..Default::default() };
            self.status.lock().unwrap().insert(table_id.clone(), state.clone());
            let limit = propagation_map.get(table_id.as_str()).map(|t| t.max_routes);
            if let Err(e) = self.reconcile_table(&table_id, &desired, limit, guard, &mut state).await {
                self.fail();
                state.error = Some(e.to_string());
            }
            self.status.lock().unwrap().insert(table_id, state);
        }
        Ok(self.status.lock().unwrap().values().all(|s| s.converged))
    }

    pub fn status_json(&self) -> serde_json::Value {
        serde_json::to_value(&*self.status.lock().unwrap()).unwrap_or_default()
    }
}
