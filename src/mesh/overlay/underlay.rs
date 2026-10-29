//! Keeps tunnel packets on the underlay.
//!
//! Babel learns routes that cover tunnel endpoints (a remote VPC's CIDR covers its relays). If the
//! kernel routed a tunnel's own GRE packets by those routes, they would recurse into the overlay.
//! So locally sent GRE packets look up a dedicated table first (`ip rule ... ipproto gre`), holding
//! one host route per tunnel endpoint, copied from the best main-table route that is not a Babel
//! route and not via a tunnel. With no such route the entry is `unreachable`: the tunnel goes quiet
//! and Babel routes around it, instead of tunnelling through itself.
//!
//! Relays also originate their VPC's CIDRs as kernel routes via the VPC router, tagged with
//! `PROTOCOL`, which babeld redistributes.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use ipnet::{IpNet, Ipv4Net};
use serde::Serialize;
use serde_json::Value;

use super::tunnel;
use crate::commands::argv;
use crate::error::{Error, Result};

/// Routing table and rule priority for endpoint pins.
pub const TABLE: u32 = 4242;
/// Route protocol number marking kernel routes this mode owns.
pub const PROTOCOL: u32 = 249;
const BABEL_PROTOCOL: &str = "babel";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Pin {
    Via { gateway: Option<Ipv4Addr>, dev: String },
    Unreachable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub dst: Ipv4Net,
    pub metric: u64,
    pub protocol: String,
    pub kind: String,
    /// (gateway, dev) per next hop; one for a single-path route.
    pub hops: Vec<(Option<Ipv4Addr>, String)>,
}

impl Route {
    fn overlay(&self) -> bool {
        self.protocol == BABEL_PROTOCOL
            || self.protocol == "42"
            || self.hops.iter().any(|(_, dev)| dev.starts_with(tunnel::PREFIX))
    }

    fn pin(&self) -> Pin {
        match (self.kind.as_str(), self.hops.first()) {
            ("unicast", Some((gateway, dev))) => Pin::Via { gateway: *gateway, dev: dev.clone() },
            _ => Pin::Unreachable,
        }
    }
}

fn text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// IPv4 routes from `ip -json route show table <t>`.
pub fn parse_routes(data: &Value) -> Result<Vec<Route>> {
    let routes = data.as_array().ok_or_else(|| Error::Backend("ip -json route: expected an array".into()))?;
    let mut parsed = vec![];
    for route in routes {
        let Some(dst) = route["dst"].as_str() else { continue };
        let dst = match dst {
            "default" => Ipv4Net::default(),
            d if d.contains('/') => match d.parse() {
                Ok(net) => net,
                Err(_) => continue,
            },
            d => match d.parse::<Ipv4Addr>() {
                Ok(a) => Ipv4Net::from(a),
                Err(_) => continue,
            },
        };
        let hop =
            |h: &Value| (h["gateway"].as_str().and_then(|g| g.parse().ok()), h["dev"].as_str().unwrap_or_default().to_string());
        let hops = match route["nexthops"].as_array() {
            Some(list) => list.iter().map(hop).collect(),
            None if route["dev"].is_string() => vec![hop(route)],
            None => vec![],
        };
        parsed.push(Route {
            dst,
            metric: route["metric"].as_u64().unwrap_or(0),
            protocol: text(&route["protocol"]).unwrap_or_default(),
            kind: route["type"].as_str().unwrap_or("unicast").to_string(),
            hops,
        });
    }
    Ok(parsed)
}

/// Longest-prefix match over `main`, ignoring overlay routes.
pub fn underlay_pin(main: &[Route], endpoint: Ipv4Addr) -> Pin {
    main.iter()
        .filter(|r| !r.overlay() && r.dst.contains(&endpoint))
        .max_by(|a, b| a.dst.prefix_len().cmp(&b.dst.prefix_len()).then(b.metric.cmp(&a.metric)))
        .map_or(Pin::Unreachable, Route::pin)
}

/// The VPC router, from the main table's preferred non-overlay default route.
pub fn default_gateway(main: &[Route]) -> Option<(Ipv4Addr, String)> {
    main.iter()
        .filter(|r| r.dst.prefix_len() == 0 && r.kind == "unicast" && !r.overlay())
        .min_by_key(|r| r.metric)
        .and_then(|r| r.hops.first())
        .and_then(|(gateway, dev)| gateway.map(|g| (g, dev.clone())))
}

fn pin_args(dst: &str, pin: &Pin, table: Option<u32>) -> Vec<String> {
    let mut args = argv(["ip", "route", "replace"]);
    match pin {
        Pin::Unreachable => args.extend(argv(["unreachable", dst])),
        Pin::Via { gateway, dev } => {
            args.push(dst.to_string());
            if let Some(gateway) = gateway {
                args.extend(argv(["via", &gateway.to_string()]));
            }
            args.extend(argv(["dev", dev.as_str()]));
        }
    }
    if let Some(table) = table {
        args.extend(argv(["table", &table.to_string()]));
    }
    args.extend(argv(["proto", &PROTOCOL.to_string()]));
    args
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Desired {
    pub pins: BTreeMap<Ipv4Addr, Pin>,
    /// VPC CIDRs this relay originates, via the VPC router.
    pub originate: BTreeMap<Ipv4Net, Pin>,
}

pub fn desired(main: &[Route], endpoints: &BTreeSet<Ipv4Addr>, originate: &[IpNet]) -> Desired {
    let pins = endpoints.iter().map(|e| (*e, underlay_pin(main, *e))).collect();
    let originate = match default_gateway(main) {
        Some((gateway, dev)) => originate
            .iter()
            .filter_map(|n| match n {
                IpNet::V4(n) => Some((n.trunc(), Pin::Via { gateway: Some(gateway), dev: dev.clone() })),
                IpNet::V6(_) => None,
            })
            .collect(),
        None => BTreeMap::new(),
    };
    Desired { pins, originate }
}

/// Whether `ip -json rule show` already sends GRE to the pin table.
pub fn has_rule(rules: &Value) -> bool {
    let table = TABLE.to_string();
    rules
        .as_array()
        .into_iter()
        .flatten()
        .any(|r| r["priority"].as_u64() == Some(u64::from(TABLE)) && text(&r["table"]).as_deref() == Some(table.as_str()))
}

pub fn rule_add() -> Vec<String> {
    let table = TABLE.to_string();
    argv(["ip", "rule", "add", "priority", &table, "ipproto", "47", "lookup", &table])
}

pub fn rule_del() -> Vec<String> {
    argv(["ip", "rule", "del", "priority", &TABLE.to_string()])
}

/// `ip` argv lists that move the pin table, the rule and originated routes to `desired`.
pub fn plan(desired: &Desired, pinned: &[Route], main: &[Route], rule: bool) -> Vec<Vec<String>> {
    let mut commands = vec![];
    if !rule {
        commands.push(rule_add());
    }
    let current: BTreeMap<Ipv4Addr, Pin> =
        pinned.iter().filter(|r| r.dst.prefix_len() == 32).map(|r| (r.dst.addr(), r.pin())).collect();
    for route in pinned {
        if route.dst.prefix_len() != 32 || !desired.pins.contains_key(&route.dst.addr()) {
            commands.push(argv(["ip", "route", "del", &route.dst.to_string(), "table", &TABLE.to_string()]));
        }
    }
    for (endpoint, pin) in &desired.pins {
        if current.get(endpoint) != Some(pin) {
            commands.push(pin_args(&format!("{endpoint}/32"), pin, Some(TABLE)));
        }
    }
    let owned: Vec<&Route> = main.iter().filter(|r| r.protocol == PROTOCOL.to_string()).collect();
    for route in &owned {
        if !desired.originate.contains_key(&route.dst) {
            commands.push(argv(["ip", "route", "del", &route.dst.to_string(), "proto", &PROTOCOL.to_string()]));
        }
    }
    for (net, pin) in &desired.originate {
        if !owned.iter().any(|r| r.dst == *net && r.pin() == *pin) {
            commands.push(pin_args(&net.to_string(), pin, None));
        }
    }
    commands
}

/// Commands that remove the rule, the pin table and originated routes.
pub fn withdraw(pinned: &[Route], main: &[Route], rule: bool) -> Vec<Vec<String>> {
    let mut commands = plan(&Desired::default(), pinned, main, true);
    if rule {
        commands.push(rule_del());
    }
    commands
}
