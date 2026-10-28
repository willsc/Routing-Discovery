mod common;

use common::root;
use route_discovery::backends::probe_plan;
use route_discovery::config::{load, parse, read_toml};
use route_discovery::error::Error;
use route_discovery::frr_export::frr_config;
use toml::{Table, Value};

fn linux_raw() -> Table {
    read_toml(&root().join("examples/linux.toml")).unwrap()
}

fn candidate(raw: &mut Table, index: usize) -> &mut Table {
    raw["routes"].as_array_mut().unwrap()[0]["candidates"].as_array_mut().unwrap()[index].as_table_mut().unwrap()
}

fn probe0(raw: &mut Table, index: usize) -> &mut Table {
    candidate(raw, index)["probes"].as_array_mut().unwrap()[0].as_table_mut().unwrap()
}

fn rejected(raw: &Table) -> bool {
    matches!(parse(raw), Err(Error::Config(_)))
}

#[test]
fn all_examples_validate() {
    for name in ["linux", "aws", "frr"] {
        assert!(!load(root().join(format!("examples/{name}.toml"))).unwrap().routes.is_empty());
    }
}

#[test]
fn unknown_key_and_duplicate_prefix_rejected() {
    let mut raw = linux_raw();
    raw["health"].as_table_mut().unwrap().insert("sucesses".into(), Value::Integer(3));
    assert!(rejected(&raw));
    raw["health"].as_table_mut().unwrap().remove("sucesses");
    let routes = raw["routes"].as_array_mut().unwrap();
    routes.push(routes[0].clone());
    assert!(rejected(&raw));
}

#[test]
fn unpinned_probes_rejected() {
    let mut raw = linux_raw();
    probe0(&mut raw, 0).remove("mark");
    assert!(rejected(&raw));
}

#[test]
fn shared_probe_mark_rejected() {
    let mut raw = linux_raw();
    probe0(&mut raw, 1).insert("mark".into(), Value::Integer(10101));
    assert!(rejected(&raw));
}

#[test]
fn strict_types_and_ranges() {
    for (key, value) in [
        ("interval", Value::Float(f64::NAN)),
        ("failures", Value::Boolean(true)),
        ("failures", Value::Float(3.0)),
        ("timeout", Value::Integer(5)),
        ("stale_after", Value::Integer(0)),
    ] {
        let mut raw = linux_raw();
        raw["health"].as_table_mut().unwrap().insert(key.into(), value);
        assert!(rejected(&raw), "{key} accepted");
    }
}

#[test]
fn injection_in_device_rejected() {
    let mut raw = linux_raw();
    candidate(&mut raw, 0).insert("device".into(), Value::String("wg0;reboot".into()));
    assert!(rejected(&raw));
}

#[test]
fn aws_rejects_ecmp_and_missing_path_contract() {
    let mut raw = read_toml(&root().join("examples/aws.toml")).unwrap();
    let route = raw["routes"].as_array_mut().unwrap()[0].as_table_mut().unwrap();
    route.insert("max_paths".into(), Value::Integer(2));
    assert!(rejected(&raw));
    raw["routes"].as_array_mut().unwrap()[0].as_table_mut().unwrap().insert("max_paths".into(), Value::Integer(1));
    probe0(&mut raw, 0).remove("external_path");
    assert!(rejected(&raw));
}

#[test]
fn bgp_protocol_cannot_be_claimed() {
    let mut raw = linux_raw();
    raw["backend"].as_table_mut().unwrap().insert("protocol".into(), Value::Integer(186));
    assert!(rejected(&raw));
}

#[test]
fn noncanonical_prefix_rejected() {
    let mut raw = linux_raw();
    raw["routes"].as_array_mut().unwrap()[0].as_table_mut().unwrap().insert("prefix".into(), "10.20.0.1/16".into());
    assert!(rejected(&raw));
}

#[test]
fn plan_has_terminal_route_and_two_isolated_tables() {
    let script = probe_plan(&parse(&linux_raw()).unwrap()).unwrap();
    assert!(script.contains("unreachable default table 10101"));
    assert!(script.contains("unreachable default table 10102"));
    assert!(script.contains("fwmark 10101/0xffffffff lookup 10101"));
    assert!(!script.contains("flush"));
}

#[test]
fn frr_export_has_prefix_and_tag_filter() {
    let config = load(root().join("examples/frr.toml")).unwrap();
    let text = frr_config(&config, "10.0.1.10", "10.0.1.20", 64512, 100).unwrap();
    for fragment in [
        "match tag 42420",
        "permit 10.20.0.0/16",
        "neighbor 10.0.1.20 bfd",
        "route-map RD-IN deny 10",
        "redistribute static route-map RD-STATIC4",
    ] {
        assert!(text.contains(fragment), "{fragment}");
    }
}
