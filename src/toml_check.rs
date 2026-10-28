//! Strict TOML accessors: a typo or wrong type in routing policy must never be ignored.

use std::net::IpAddr;

use ipnet::IpNet;
use toml::{Table, Value};

use crate::error::{config_err, Result};

pub fn table<'a>(value: &'a Value, where_: &str) -> Result<&'a Table> {
    value.as_table().map_or_else(|| config_err(format!("{where_}: expected a table")), Ok)
}

pub fn check_keys(raw: &Table, allowed: &[&str], where_: &str) -> Result<()> {
    let mut unknown: Vec<&str> = raw.keys().map(String::as_str).filter(|k| !allowed.contains(k)).collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    config_err(format!("{where_}: unknown keys: {}", unknown.join(", ")))
}

/// Optional sub-table; absent means empty.
pub fn sub_table<'a>(raw: &'a Table, key: &str, empty: &'a Table) -> Result<&'a Table> {
    raw.get(key).map_or(Ok(empty), |v| table(v, key))
}

/// Integers or floats within a closed range (TOML integers are accepted for float settings).
pub fn float(value: Option<&Value>, default: f64, name: &str, low: f64, high: f64) -> Result<f64> {
    let number = match value {
        None => default,
        Some(Value::Integer(i)) => *i as f64,
        Some(Value::Float(f)) => *f,
        Some(_) => return config_err(format!("{name}: expected a number")),
    };
    if !number.is_finite() || !(low..=high).contains(&number) {
        return config_err(format!("{name}: expected number in [{low}, {high}]"));
    }
    Ok(number)
}

pub fn int(value: Option<&Value>, default: i64, name: &str, low: i64, high: i64) -> Result<i64> {
    let number = match value {
        None => default,
        Some(Value::Integer(i)) => *i,
        Some(Value::Float(_)) => return config_err(format!("{name}: expected integer in [{low}, {high}]")),
        Some(_) => return config_err(format!("{name}: expected a number")),
    };
    if !(low..=high).contains(&number) {
        return config_err(format!("{name}: expected integer in [{low}, {high}]"));
    }
    Ok(number)
}

pub fn required_int(value: Option<&Value>, name: &str, low: i64, high: i64) -> Result<i64> {
    match value {
        None => config_err(format!("{name}: expected a number")),
        some => int(some, 0, name, low, high),
    }
}

pub fn boolean(value: Option<&Value>, default: bool, message: &str) -> Result<bool> {
    match value {
        None => Ok(default),
        Some(Value::Boolean(b)) => Ok(*b),
        Some(_) => config_err(message),
    }
}

pub fn optional_string(value: Option<&Value>, message: &str) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => config_err(message),
    }
}

pub fn array<'a>(value: Option<&'a Value>, message: &str) -> Result<&'a Vec<Value>> {
    value.and_then(Value::as_array).map_or_else(|| config_err(message), Ok)
}

fn charset(value: &str, extra: &str) -> bool {
    value.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

pub fn is_name(value: &str) -> bool {
    (1..=64).contains(&value.len()) && charset(value, "_.-")
}

pub fn name(value: Option<&Value>, where_: &str) -> Result<String> {
    match value.and_then(Value::as_str) {
        Some(s) if is_name(s) => Ok(s.to_string()),
        _ => config_err(format!("{where_}: use 1–64 letters, digits, dots, underscores or hyphens")),
    }
}

pub fn is_interface(value: &str) -> bool {
    (1..=15).contains(&value.len()) && charset(value, "_.-") && !value.starts_with('-')
}

pub fn is_owner_tag(value: &str) -> bool {
    (1..=128).contains(&value.len()) && charset(value, "_./:-")
}

/// `[a-z]{2}(-[a-z]+)+-\d`, e.g. eu-west-2 or us-gov-east-1.
pub fn is_region(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    let lower = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase());
    parts.len() >= 3
        && parts[0].len() == 2
        && lower(parts[0])
        && parts[1..parts.len() - 1].iter().all(|p| lower(p))
        && parts[parts.len() - 1].len() == 1
        && parts[parts.len() - 1].chars().all(|c| c.is_ascii_digit())
}

/// `{kind}-[0-9a-f]{8,17}`, e.g. rtb-0123456789abcdef0.
pub fn is_resource(value: &str, kind: &str) -> bool {
    value
        .strip_prefix(kind)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|id| (8..=17).contains(&id.len()) && id.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)))
}

pub fn resource(value: Option<&Value>, kind: &str) -> Result<String> {
    match value.and_then(Value::as_str) {
        Some(s) if is_resource(s, kind) => Ok(s.to_string()),
        _ => config_err(format!("expected a {kind} resource ID")),
    }
}

pub fn parse_address(value: &str) -> Option<IpAddr> {
    value.parse().ok()
}

pub fn address(value: Option<&Value>, where_: &str) -> Result<IpAddr> {
    match value.and_then(Value::as_str).and_then(parse_address) {
        Some(ip) => Ok(ip),
        None => config_err(format!("{where_}: use a literal IP address (no DNS dependency)")),
    }
}

/// Canonical network: host bits must be zero; a bare address is a host route.
pub fn parse_network(value: &str) -> Option<IpNet> {
    let net = match value.parse::<IpNet>() {
        Ok(net) => net,
        Err(_) => IpNet::from(value.parse::<IpAddr>().ok()?),
    };
    (net.trunc() == net).then_some(net)
}

pub fn same_family(a: IpAddr, b: IpAddr) -> bool {
    a.is_ipv4() == b.is_ipv4()
}
