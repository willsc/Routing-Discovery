//! Exercise real iproute2 commands in a new user+network namespace, never the host.
//! Run with `cargo test --test kernel_smoke -- --ignored`.

use std::process::Command;

use route_discovery::backends::{probe_plan, validate_probe_paths, Backend, Linux};
use route_discovery::commands::{argv, Runner, SystemRunner};
use route_discovery::config::load;
use route_discovery::policy::{Action, Decision};

const PARENT: &str = "RD_SMOKE_PARENT_NETNS";

fn netns() -> String {
    std::fs::metadata("/proc/self/ns/net").map(|m| std::os::unix::fs::MetadataExt::ino(&m).to_string()).unwrap()
}

async fn ip(args: &[&str]) {
    let mut command = vec!["ip"];
    command.extend(args);
    SystemRunner.run(&argv(command), 5.0).await.unwrap();
}

async fn smoke() {
    let config = load(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/linux.toml")).unwrap();
    ip(&["link", "set", "lo", "up"]).await;
    for device in ["wg-a", "wg-b"] {
        ip(&["link", "add", device, "type", "dummy"]).await;
        ip(&["link", "set", device, "up"]).await;
    }
    for line in probe_plan(&config).unwrap().lines().filter(|l| l.starts_with("ip ")) {
        SystemRunner.run(&argv(line.split_whitespace()), 5.0).await.unwrap();
    }
    validate_probe_paths(&config, &SystemRunner).await.unwrap();
    let backend = Linux::new(&config, std::sync::Arc::new(SystemRunner));
    let route = config.routes[0].clone();
    let steps = [
        Decision::route(&["az-a"]),
        Decision::route(&["az-b"]),
        Decision::route(&["az-a", "az-b"]),
        Decision::new(Action::Unreachable, ""),
        Decision::route(&["az-a"]),
        Decision::new(Action::Withdraw, ""),
    ];
    for decision in &steps {
        assert!(backend.apply(&route, decision).await.unwrap(), "{decision:?}");
        validate_probe_paths(&config, &SystemRunner).await.unwrap();
    }
    for (index, device) in ["wg-a", "wg-b"].iter().enumerate() {
        ip(&["-6", "addr", "add", &format!("2001:db8:{}::1/64", index + 1), "dev", device, "nodad"]).await;
    }
    let mut route6 = route.clone();
    route6.prefix = "2001:db8:20::/64".parse().unwrap();
    for (i, c) in route6.candidates.iter_mut().enumerate() {
        c.gateway = Some(format!("2001:db8:{}::2", i + 1).parse().unwrap());
    }
    for decision in [
        Decision::route(&["az-a"]),
        Decision::route(&["az-a", "az-b"]),
        Decision::new(Action::Unreachable, ""),
        Decision::new(Action::Withdraw, ""),
    ] {
        assert!(backend.apply(&route6, &decision).await.unwrap(), "{decision:?}");
    }
    println!("PASS: real IPv4/IPv6 install, failover, ECMP, unreachable, withdrawal, and probe isolation");
}

#[test]
#[ignore = "needs unprivileged user namespaces and iproute2"]
fn kernel_smoke() {
    match std::env::var(PARENT) {
        Err(_) => {
            let status = Command::new("unshare")
                .args(["--user", "--map-root-user", "--net"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", "kernel_smoke", "--ignored", "--nocapture"])
                .env(PARENT, netns())
                .status()
                .unwrap();
            assert!(status.success());
        }
        Ok(parent) => {
            assert_ne!(parent, netns(), "refusing to run outside a private network namespace");
            tokio::runtime::Runtime::new().unwrap().block_on(smoke());
        }
    }
}
