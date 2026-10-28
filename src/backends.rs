//! Reconcile observed state, never flush a table or assume a write succeeded.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;

use crate::aws::{Ec2, RouteRequest};
use crate::commands::{argv, Runner, SystemRunner, DEFAULT_TIMEOUT};
use crate::config::{Backend as BackendConfig, BackendKind, Candidate, Config, Route};
use crate::error::{backend_err, Error, Result};
use crate::policy::{Action, Decision};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Observed {
    pub paths: Vec<String>,
    pub action: Action,
    pub usable: bool,
}

impl Default for Observed {
    fn default() -> Self {
        Observed { paths: Vec::new(), action: Action::Withdraw, usable: true }
    }
}

impl Observed {
    pub fn unreachable() -> Self {
        Observed { action: Action::Unreachable, ..Default::default() }
    }
}

pub fn wanted(decision: &Decision) -> Observed {
    Observed { paths: decision.paths.clone(), action: decision.action, usable: true }
}

#[async_trait]
pub trait Backend: Send + Sync {
    async fn current(&self, route: &Route) -> Result<Observed>;
    /// True only once a readback confirms the decision is installed.
    async fn apply(&self, route: &Route, decision: &Decision) -> Result<bool>;
}

pub fn family(route: &Route) -> &'static str {
    if route.is_v6() {
        "-6"
    } else {
        "-4"
    }
}

/// Render a JSON scalar the way iproute2 comparisons need: strings raw, numbers as digits.
fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// ip -N prints numeric route types as well as numeric protocol/table IDs.
pub fn route_type(record: &Value) -> String {
    match scalar(record.get("type")).as_deref() {
        None | Some("1") => "unicast".into(),
        Some("7") => "unreachable".into(),
        Some(other) => other.into(),
    }
}

fn parse_rows(output: &str) -> Result<Vec<Value>> {
    serde_json::from_str(output).map_err(|e| Error::Backend(format!("unexpected ip JSON: {e}")))
}

/// Isolated in-memory FIB: does not read credentials, invoke ip, or call AWS.
#[derive(Default)]
pub struct DryRun {
    pub routes: Mutex<HashMap<String, Observed>>,
    pub changes: Mutex<Vec<(String, Decision)>>,
}

#[async_trait]
impl Backend for DryRun {
    async fn current(&self, route: &Route) -> Result<Observed> {
        Ok(self.routes.lock().unwrap().get(&route.key()).cloned().unwrap_or_default())
    }

    async fn apply(&self, route: &Route, decision: &Decision) -> Result<bool> {
        if decision.action == Action::Hold {
            return Ok(true);
        }
        let value = wanted(decision);
        let mut routes = self.routes.lock().unwrap();
        if routes.get(&route.key()).cloned().unwrap_or_default() != value {
            routes.insert(route.key(), value);
            self.changes.lock().unwrap().push((route.key(), decision.clone()));
        }
        Ok(true)
    }
}

pub struct Linux {
    b: BackendConfig,
    run: Arc<dyn Runner>,
}

impl Linux {
    pub fn new(config: &Config, runner: Arc<dyn Runner>) -> Self {
        Linux { b: config.backend.clone(), run: runner }
    }
}

#[async_trait]
impl Backend for Linux {
    async fn current(&self, route: &Route) -> Result<Observed> {
        let prefix = route.key();
        let args = argv(["ip", family(route), "-N", "-j", "route", "show", "table", &self.b.table.to_string(), "exact", &prefix]);
        let output = match self.run.run(&args, DEFAULT_TIMEOUT).await {
            Err(Error::Backend(e)) if e.contains("FIB table does not exist") => return Ok(Observed::default()),
            other => other?,
        };
        let records = parse_rows(&output)?;
        let Some(record) = records.first() else { return Ok(Observed::default()) };
        if records.len() != 1 {
            return backend_err(format!("{prefix}: competing routes; refusing to change them"));
        }
        let metric = record.get("metric").map_or(Some(0), Value::as_u64);
        if scalar(record.get("protocol")) != Some(self.b.protocol.to_string()) || metric != Some(self.b.metric.into()) {
            return backend_err(format!("{prefix}: route is not owned by this daemon (protocol/metric)"));
        }
        let kind = route_type(record);
        if kind == "unreachable" {
            return Ok(Observed::unreachable());
        }
        if kind != "unicast" || record.get("nhid").is_some() {
            return backend_err(format!("{prefix}: unsupported existing route representation"));
        }
        let hops = match record.get("nexthops").and_then(Value::as_array) {
            Some(hops) => hops.iter().collect::<Vec<_>>(),
            None => vec![record],
        };
        let mut ids = Vec::new();
        for hop in hops {
            let gateway = hop.get("gateway").and_then(Value::as_str);
            let dev = hop.get("dev").and_then(Value::as_str);
            let matches: Vec<&Candidate> = route
                .candidates
                .iter()
                .filter(|c| c.gateway.map(|g| g.to_string()).as_deref() == gateway && c.device.as_deref() == dev)
                .collect();
            let weight = hop.get("weight").map_or(Some(1), Value::as_u64);
            let encap = hop.get("encap").is_some_and(|e| !e.is_null() && e != &Value::Bool(false) && e != "");
            if matches.len() != 1 || weight != Some(1) || encap {
                return backend_err(format!("{prefix}: unconfigured next hop or route attributes"));
            }
            ids.push(matches[0].id.clone());
        }
        ids.sort();
        Ok(Observed { paths: ids, action: Action::Route, usable: true })
    }

    async fn apply(&self, route: &Route, decision: &Decision) -> Result<bool> {
        let before = self.current(route).await?;
        if decision.action == Action::Hold || before == wanted(decision) {
            return Ok(true);
        }
        let mut args = argv(["ip", family(route), "route"]);
        if decision.action == Action::Withdraw {
            args.push("del".into());
            if before.action == Action::Unreachable {
                args.push("unreachable".into());
            }
        } else {
            args.push("replace".into());
            if decision.action == Action::Unreachable {
                args.push("unreachable".into());
            }
        }
        args.push(route.key());
        args.extend(argv([
            "table",
            &self.b.table.to_string(),
            "proto",
            &self.b.protocol.to_string(),
            "metric",
            &self.b.metric.to_string(),
        ]));
        if decision.action == Action::Route {
            let selected: Vec<&Candidate> = route.candidates.iter().filter(|c| decision.paths.contains(&c.id)).collect();
            let multipath = selected.len() > 1;
            for c in selected {
                if multipath {
                    args.push("nexthop".into());
                }
                if let Some(gateway) = c.gateway {
                    args.extend(argv(["via".to_string(), gateway.to_string()]));
                }
                args.extend(argv(["dev", c.device.as_deref().unwrap_or_default()]));
                if multipath {
                    args.extend(argv(["weight", "1"]));
                }
            }
        }
        self.run.run(&args, DEFAULT_TIMEOUT).await?;
        Ok(self.current(route).await? == wanted(decision))
    }
}

/// Single writer only: EC2 route updates have no compare-and-swap primitive.
pub struct Aws {
    b: BackendConfig,
    client: Arc<dyn Ec2>,
}

impl Aws {
    pub fn new(config: &Config, client: Arc<dyn Ec2>) -> Self {
        Aws { b: config.backend.clone(), client }
    }

    fn table_id(&self) -> String {
        self.b.route_table_id.clone().unwrap_or_default()
    }

    fn request(&self, route: &Route, target: Option<String>) -> RouteRequest {
        RouteRequest { table_id: self.table_id(), prefix: route.key(), ipv6: route.is_v6(), network_interface_id: target }
    }
}

#[async_trait]
impl Backend for Aws {
    async fn current(&self, route: &Route) -> Result<Observed> {
        let id = self.table_id();
        let tables = self.client.describe_route_tables(std::slice::from_ref(&id)).await?;
        if tables.len() != 1 || tables[0].id != id {
            return backend_err("AWS route table is missing or unexpected");
        }
        let table = &tables[0];
        if table.tags.get(&self.b.owner_tag) != Some(&self.b.owner_value) {
            return backend_err("AWS route table is missing its required ownership tag");
        }
        let prefix = route.key();
        let found: Vec<_> = table
            .routes
            .iter()
            .filter(|r| {
                let destination = if route.is_v6() { &r.destination_ipv6_cidr } else { &r.destination_cidr };
                destination.as_deref() == Some(prefix.as_str())
            })
            .collect();
        let Some(record) = found.first() else { return Ok(Observed::default()) };
        if found.len() != 1 {
            return backend_err("unexpected duplicate AWS routes");
        }
        if !record.is_static() {
            return backend_err(format!("{prefix}: refusing to modify a local or propagated AWS route"));
        }
        let matches: Vec<String> = route
            .candidates
            .iter()
            .filter(|c| c.aws_target.is_some() && c.aws_target == record.network_interface_id)
            .map(|c| c.id.clone())
            .collect();
        if matches.len() != 1 {
            return backend_err(format!("{prefix}: existing AWS target is outside the configured allowlist"));
        }
        Ok(Observed { paths: matches, action: Action::Route, usable: record.active() })
    }

    async fn apply(&self, route: &Route, decision: &Decision) -> Result<bool> {
        let before = self.current(route).await?;
        if decision.action == Action::Hold || before == wanted(decision) {
            return Ok(true);
        }
        if decision.action == Action::Withdraw {
            self.client.delete_route(&self.request(route, None)).await?;
        } else {
            let candidate = decision
                .paths
                .first()
                .and_then(|id| route.candidates.iter().find(|c| &c.id == id))
                .ok_or_else(|| Error::Backend("AWS decision has no configured target".into()))?;
            let request = self.request(route, candidate.aws_target.clone());
            if before.action == Action::Withdraw {
                self.client.create_route(&request).await?;
            } else {
                self.client.replace_route(&request).await?;
            }
        }
        // Eventual consistency: leave desired state pending until a subsequent read agrees.
        Ok(self.current(route).await? == wanted(decision))
    }
}

/// Own tagged static routes; FRR owns the BGP/BFD sessions and advertisements.
pub struct Frr {
    b: BackendConfig,
    run: Arc<dyn Runner>,
}

impl Frr {
    pub fn new(config: &Config, runner: Arc<dyn Runner>) -> Self {
        Frr { b: config.backend.clone(), run: runner }
    }

    pub fn command(&self, route: &Route, candidate: &Candidate) -> String {
        let mut parts = vec![if route.is_v6() { "ipv6" } else { "ip" }.to_string(), "route".into(), route.key()];
        if let Some(gateway) = candidate.gateway {
            parts.push(gateway.to_string());
        }
        parts.extend([candidate.device.clone().unwrap_or_default(), "tag".into(), self.b.frr_tag.to_string()]);
        parts.join(" ")
    }
}

#[async_trait]
impl Backend for Frr {
    async fn current(&self, route: &Route) -> Result<Observed> {
        let config = self.run.run(&argv(["vtysh", "-c", "show running-config"]), DEFAULT_TIMEOUT).await?;
        let start = format!("{} route {} ", if route.is_v6() { "ipv6" } else { "ip" }, route.key());
        let expected: HashMap<String, &str> = route.candidates.iter().map(|c| (self.command(route, c), c.id.as_str())).collect();
        let mut ids = Vec::new();
        for line in config.lines() {
            // Restrict to global static routes; VRF commands start with whitespace.
            if !line.starts_with(&start) {
                continue;
            }
            match expected.get(line) {
                Some(id) => ids.push(id.to_string()),
                None => return backend_err(format!("{}: unowned or unsupported FRR static route", route.key())),
            }
        }
        ids.sort();
        let action = if ids.is_empty() { Action::Withdraw } else { Action::Route };
        Ok(Observed { paths: ids, action, usable: true })
    }

    async fn apply(&self, route: &Route, decision: &Decision) -> Result<bool> {
        let before = self.current(route).await?;
        if decision.action == Action::Hold || before == wanted(decision) {
            return Ok(true);
        }
        // Add first, then remove. Changes are not atomic in FRR; transient ECMP is possible.
        let after: HashSet<&String> = decision.paths.iter().collect();
        let current: HashSet<&String> = before.paths.iter().collect();
        let mut commands = vec!["configure terminal".to_string()];
        commands.extend(
            route.candidates.iter().filter(|c| after.contains(&c.id) && !current.contains(&c.id)).map(|c| self.command(route, c)),
        );
        commands.extend(
            route
                .candidates
                .iter()
                .filter(|c| current.contains(&c.id) && !after.contains(&c.id))
                .map(|c| format!("no {}", self.command(route, c))),
        );
        commands.push("end".into());
        let mut args = vec!["vtysh".to_string()];
        for command in commands {
            args.extend(["-c".to_string(), command]);
        }
        let output = self.run.run(&args, DEFAULT_TIMEOUT).await?;
        if output.lines().any(|line| line.trim_start().starts_with('%')) {
            return backend_err(format!("FRR rejected route commands: {}", output.trim()));
        }
        // Verifies static configuration, not BGP convergence or kernel installation.
        Ok(self.current(route).await? == wanted(decision))
    }
}

pub async fn make_backend(config: &Config, apply: bool) -> Result<Arc<dyn Backend>> {
    if !apply {
        return Ok(Arc::new(DryRun::default()));
    }
    Ok(match config.backend.kind {
        BackendKind::Linux => Arc::new(Linux::new(config, Arc::new(SystemRunner))),
        BackendKind::Frr => Arc::new(Frr::new(config, Arc::new(SystemRunner))),
        BackendKind::Aws => {
            let region = config.backend.region.as_deref().unwrap_or_default();
            Arc::new(Aws::new(config, crate::aws::client(region).await?))
        }
    })
}

fn host_prefix(route: &Route, address: impl std::fmt::Display) -> String {
    format!("{address}{}", if route.is_v6() { "/128" } else { "/32" })
}

/// Return a reviewable shell script. Never alter the operator's policy routing.
pub fn probe_plan(config: &Config) -> Result<String> {
    if config.backend.kind == BackendKind::Aws {
        return backend_err("AWS probe paths must be provisioned at their external vantage points");
    }
    let mut lines = vec![
        "#!/bin/sh".to_string(),
        "set -eu".into(),
        "# Reserve each listed table and rule priority exclusively for probes.".into(),
        "# Run once after checking for collisions; Linux permits duplicate policy rules.".into(),
    ];
    let mut seen = BTreeSet::new();
    for route in &config.routes {
        let fam = family(route);
        for c in &route.candidates {
            let device = c.device.as_deref().unwrap_or_default();
            for p in &c.probes {
                let mark = p.mark.unwrap_or_default();
                if seen.insert((fam, mark)) {
                    lines.push(format!("ip {fam} route replace unreachable default table {mark} proto 196 metric 32760"));
                    lines.push(format!("ip {fam} rule add priority {mark} fwmark {mark}/0xffffffff lookup {mark}"));
                    if let Some(gateway) = c.gateway {
                        lines.push(format!(
                            "ip {fam} route replace {} dev {device} scope link table {mark} proto 196",
                            host_prefix(route, gateway)
                        ));
                    }
                }
                let via = c.gateway.map(|g| format!(" via {g}")).unwrap_or_default();
                lines.push(format!(
                    "ip {fam} route replace {}{via} dev {device} table {mark} proto 196",
                    host_prefix(route, p.host)
                ));
            }
        }
    }
    Ok(lines.join("\n") + "\n")
}

/// Confirm each probe's marked lookup resolves to its own table, device and gateway.
#[async_trait]
pub trait PathValidator: Send + Sync {
    async fn validate(&self, config: &Config) -> Result<()>;
}

pub struct ProbePathValidator(pub Arc<dyn Runner>);

impl Default for ProbePathValidator {
    fn default() -> Self {
        ProbePathValidator(Arc::new(SystemRunner))
    }
}

#[async_trait]
impl PathValidator for ProbePathValidator {
    async fn validate(&self, config: &Config) -> Result<()> {
        validate_probe_paths(config, self.0.as_ref()).await
    }
}

pub async fn validate_probe_paths(config: &Config, runner: &dyn Runner) -> Result<()> {
    if config.backend.kind == BackendKind::Aws {
        return Ok(()); // External vantage-point correctness is an operator responsibility.
    }
    for route in &config.routes {
        let fam = family(route);
        for c in &route.candidates {
            for p in &c.probes {
                let mark = p.mark.unwrap_or_default().to_string();
                let mut args = argv(["ip", fam, "-N", "-j", "route", "get", &p.host.to_string(), "mark", &mark, "oif"]);
                args.push(p.device.clone().unwrap_or_default());
                if let Some(source) = p.source {
                    args.extend(argv(["from".to_string(), source.to_string()]));
                }
                let rows = parse_rows(&runner.run(&args, DEFAULT_TIMEOUT).await?)?;
                let pinned = rows.len() == 1
                    && scalar(rows[0].get("table")).as_deref() == Some(mark.as_str())
                    && rows[0].get("dev").and_then(Value::as_str) == c.device.as_deref()
                    && rows[0].get("gateway").and_then(Value::as_str) == c.gateway.map(|g| g.to_string()).as_deref();
                if !pinned {
                    return backend_err(format!(
                        "{}/{}: probe {} is not pinned to its configured path/table",
                        route.key(),
                        c.id,
                        p.host
                    ));
                }
                // A terminal route prevents fall-through if a host route disappears.
                let show = argv(["ip", fam, "-N", "-j", "route", "show", "table", &mark, "exact", "default"]);
                let fallback = parse_rows(&runner.run(&show, DEFAULT_TIMEOUT).await?)?;
                if fallback.len() != 1 || route_type(&fallback[0]) != "unreachable" {
                    return backend_err(format!(
                        "probe table {mark} needs an unreachable default; observed {}",
                        Value::Array(fallback)
                    ));
                }
            }
        }
    }
    Ok(())
}
