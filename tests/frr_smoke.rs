//! Real FRR BGP learning/withdrawal in a private network namespace; no AWS calls.
//!
//! `FRR_ROOT=/path/to/extracted/frr cargo test --test frr_smoke -- --ignored --nocapture`
//! FRR_ROOT defaults to / for installed FRR. bgpd's no-zebra mode is used only in this harness.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use route_discovery::commands::{Runner, SystemRunner};
use route_discovery::error::{backend_err, Result};
use route_discovery::server::config::{Endpoint, ServerConfig};
use route_discovery::server::demo::demo_config;
use route_discovery::server::frr::{render, FrrSource, Source};
use route_discovery::server::journal::Journal;
use route_discovery::server::propagation::Propagator;
use route_discovery::server::rib::Rib;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const PARENT: &str = "RD_SMOKE_PARENT_NETNS";

fn netns() -> String {
    std::fs::metadata("/proc/self/ns/net").map(|m| std::os::unix::fs::MetadataExt::ino(&m).to_string()).unwrap()
}

/// Extracted packages lack host PAM configuration, so speak FRR's local VTY protocol
/// directly in this harness instead of running vtysh; production uses vtysh.
struct Vty;

impl Vty {
    async fn exchange(folder: &str, commands: &[String]) -> Result<String> {
        let mut stream = UnixStream::connect(Path::new(folder).join("bgpd.vty")).await?;
        let mut output = String::new();
        for command in std::iter::once("enable").chain(commands.iter().map(String::as_str)) {
            stream.write_all(command.as_bytes()).await?;
            stream.write_all(b"\0").await?;
            let mut data = Vec::new();
            while !data.ends_with(b"\0\0\0") {
                let mut byte = [0u8; 1];
                tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut byte))
                    .await
                    .map_err(|_| route_discovery::Error::Backend("VTY timeout".into()))??;
                data.push(byte[0]);
            }
            let mut code = [0u8; 1];
            stream.read_exact(&mut code).await?;
            let text = String::from_utf8_lossy(&data[..data.len() - 3]).into_owned();
            if code[0] != 0 {
                return backend_err(format!("FRR command failed: {command}: {text}"));
            }
            if command != "enable" {
                output.push_str(&text);
            }
        }
        Ok(output)
    }
}

#[async_trait]
impl Runner for Vty {
    async fn run(&self, args: &[String], timeout: f64) -> Result<String> {
        if args[0] != "vtysh" {
            return SystemRunner.run(args, timeout).await;
        }
        let folder = &args[args.iter().position(|a| a == "--vty_socket").unwrap() + 1];
        let commands: Vec<String> = args.windows(2).filter(|w| w[0] == "-c").map(|w| w[1].clone()).collect();
        Self::exchange(folder, &commands).await
    }
}

async fn vty(folder: &Path, commands: &[String]) {
    Vty::exchange(folder.to_str().unwrap(), commands).await.unwrap();
}

struct Harness {
    directory: tempfile::TempDir,
    root: PathBuf,
    processes: Vec<(Child, PathBuf)>,
}

impl Harness {
    fn start(&mut self, label: &str, address: &str, content: &str) {
        let folder = self.directory.path().join(label);
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("bgpd.conf"), content).unwrap();
        let log_path = folder.join("bgpd.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let library = self.root.join("usr/lib/x86_64-linux-gnu");
        let child = Command::new(self.root.join("usr/lib/frr/bgpd"))
            .args(["-S", "-Z", "-n", "-l", address, "-f"])
            .arg(folder.join("bgpd.conf"))
            .arg("--vty_socket")
            .arg(&folder)
            .arg("-i")
            .arg(folder.join("bgpd.pid"))
            .args(["-P", "0", "--log", "stdout"])
            .env("LD_LIBRARY_PATH", format!("{}:{}", library.display(), library.join("frr").display()))
            .stdout(log.try_clone().unwrap())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.processes.push((child, log_path));
    }

    fn exited(&mut self) -> bool {
        self.processes.iter_mut().any(|(p, _)| p.try_wait().ok().flatten().is_some())
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        for (process, log) in &mut self.processes {
            let _ = process.kill();
            let _ = process.wait();
            if std::thread::panicking() {
                let text = std::fs::read_to_string(&*log).unwrap_or_default();
                eprintln!("{}:\n{}", log.display(), &text[text.len().saturating_sub(6000)..]);
            }
        }
    }
}

async fn smoke(root: PathBuf) {
    let mut harness =
        Harness { directory: tempfile::Builder::new().prefix("rd-frr-").tempdir().unwrap(), root, processes: vec![] };
    let dir = harness.directory.path().to_path_buf();
    let ip = |args: &[&str]| {
        assert!(Command::new("ip").args(args).status().unwrap().success());
    };
    ip(&["link", "set", "lo", "up"]);
    for index in 1..=3 {
        ip(&["addr", "add", &format!("198.18.0.{index}/32"), "dev", "lo"]);
    }
    let mut config: ServerConfig = demo_config();
    config.endpoints = vec![Endpoint {
        id: "edge".into(),
        address: "198.18.0.1".parse().unwrap(),
        router_id: "198.18.0.1".parse().unwrap(),
        socket_dir: dir.join("edge").display().to_string(),
    }];
    for (i, peer) in config.peers.iter_mut().enumerate() {
        let address = format!("198.18.0.{}", i + 2);
        peer.address = address.parse().unwrap();
        peer.next_hops = vec![address];
        peer.bfd = false;
    }
    config.failback_delay = 0.3;

    let source = FrrSource::new(config.clone(), Arc::new(Vty));
    let mut rib = Rib::new(config.clone());
    let journal = Arc::new(Mutex::new(Journal::open(&config, None).unwrap()));
    let backend = Propagator::new(config.clone(), journal.clone(), None, false).unwrap();
    let started = Instant::now();

    harness.start(
        "edge",
        "198.18.0.1",
        &render(&config, "edge").unwrap().replace(" bgp no-rib", " bgp disable-ebgp-connected-route-check"),
    );
    for (peer, med) in config.peers.iter().zip([10, 100]) {
        let content = format!(
            "route-map OUT permit 10\n set metric {med}\nrouter bgp {asn}\n bgp router-id {address}\n no bgp ebgp-requires-policy\n \
             no bgp network import-check\n bgp disable-ebgp-connected-route-check\n neighbor 198.18.0.1 remote-as {server}\n \
             neighbor 198.18.0.1 update-source {address}\n neighbor 198.18.0.1 timers 1 3\n address-family ipv4 unicast\n  \
             network 10.20.1.0/24\n  neighbor 198.18.0.1 route-map OUT out\n exit-address-family\n",
            asn = peer.asn,
            address = peer.address,
            server = config.asn,
        );
        harness.start(&peer.id, &peer.address.to_string(), &content);
    }

    let mut expect = async |paths: usize, winner: Option<&str>| {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut last;
        loop {
            match source.read(&config.endpoints[0]).await {
                Ok(snapshot) => {
                    let now = started.elapsed().as_secs_f64();
                    rib.update("edge", snapshot.clone(), now);
                    let fib = rib.select(now);
                    if snapshot.routes.len() == paths && winner.is_none_or(|w| fib.values().any(|r| r.peer == w)) {
                        assert!(backend.reconcile(&fib, &|| true).await.unwrap());
                        return;
                    }
                    last = format!("{snapshot:?} / {fib:?}");
                }
                Err(e) => last = e.to_string(),
            }
            assert!(!harness.exited(), "FRR exited; last observation: {last}");
            assert!(Instant::now() < deadline, "timed out; last observation: {last}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let network = |asn: u32, negate: bool| -> Vec<String> {
        vec![
            "configure terminal".into(),
            format!("router bgp {asn}"),
            "address-family ipv4 unicast".into(),
            format!("{}network 10.20.1.0/24", if negate { "no " } else { "" }),
        ]
    };

    expect(2, Some("primary")).await;
    vty(&dir.join("primary"), &network(65010, true)).await;
    expect(1, Some("backup")).await;
    vty(&dir.join("primary"), &network(65010, false)).await;
    expect(2, Some("primary")).await;
    for peer in &config.peers {
        vty(&dir.join(&peer.id), &network(peer.asn, true)).await;
    }
    expect(0, None).await;
    assert!(journal.lock().unwrap().entries().unwrap().is_empty());
    println!("PASS: real FRR BGP learning, primary withdrawal, backup selection, failback and two-table simulated propagation");
}

#[test]
#[ignore = "needs FRR (set FRR_ROOT for an extracted package) and unprivileged user namespaces"]
fn frr_smoke() {
    match std::env::var(PARENT) {
        Err(_) => {
            let status = Command::new("unshare")
                .args(["--user", "--map-root-user", "--net"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", "frr_smoke", "--ignored", "--nocapture"])
                .env(PARENT, netns())
                .status()
                .unwrap();
            assert!(status.success());
        }
        Ok(parent) => {
            assert_ne!(parent, netns(), "refusing to run in the host network namespace");
            let root = PathBuf::from(std::env::var("FRR_ROOT").unwrap_or_else(|_| "/".into()));
            tokio::runtime::Runtime::new().unwrap().block_on(smoke(root));
        }
    }
}
