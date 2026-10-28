use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};

use route_discovery::backends::{make_backend, probe_plan, validate_probe_paths};
use route_discovery::bgp;
use route_discovery::commands::SystemRunner;
use route_discovery::config::{load, BackendKind, Config};
use route_discovery::daemon::Daemon;
use route_discovery::error::{config_err, Error, Result};
use route_discovery::frr_export::frr_config;
use route_discovery::mesh::{self, frr::Policy, frr::Vtysh, inventory::collect, inventory::Filter};
use route_discovery::policy::{Action, Decision};
use route_discovery::server;
use route_discovery::state::StateStore;

#[derive(Parser)]
#[command(
    name = "route-discovery",
    version,
    about = "Health-driven Linux/AWS routing, FRR BGP integration and a zero-configuration Babel mesh"
)]
struct Cli {
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "UPPER")]
enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a host-routing configuration
    Validate {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Print a reviewable shell script that provisions probe routing tables
    ProbePlan {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Verify each probe is pinned to its candidate's path
    CheckPaths {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Run the health-routing daemon
    Run {
        #[arg(short, long)]
        config: PathBuf,
        /// Write live routes (default is in-memory dry-run)
        #[arg(long)]
        apply: bool,
    },
    /// Render an FRR fragment that exports this daemon's tagged statics via BGP
    RenderFrr {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        router_id: String,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        peer_asn: i64,
        #[arg(long, default_value_t = 100)]
        med: i64,
    },
    /// Withdraw FRR runtime statics (systemd ExecStopPost)
    CleanupFrr {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        apply: bool,
    },
    /// Print a running daemon's status
    Status {
        #[arg(long, default_value = "http://127.0.0.1:9808/status")]
        url: String,
    },
    /// Deterministic failover/failback simulation, with no network changes
    Demo,
    /// Zero-configuration BGP to VPC Route Server and Transit Gateway Connect
    Bgp {
        operation: BgpOperation,
        #[command(flatten)]
        args: BgpArgs,
    },
    /// Zero-configuration Babel mesh over every eligible NIC (FRR babeld)
    Mesh {
        operation: MeshOperation,
        #[command(flatten)]
        args: MeshArgs,
    },
    /// BGP-to-VPC route-server control plane
    Server {
        operation: ServerOperation,
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Endpoint ID for render-frr
        #[arg(long)]
        endpoint: Option<String>,
        /// Perform AWS route writes
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BgpOperation {
    /// Print this instance, its AWS BGP peerings, tunnels and announced prefixes (JSON)
    Discover,
    /// Print the bgpd configuration derived from discovery
    RenderFrr,
    /// Print tunnel commands and the bgpd changes a reload would make
    Plan,
    /// Keep GRE tunnels and bgpd in step with AWS and local interfaces
    Run,
    /// Remove the bgpd peerings and owned GRE tunnels
    Withdraw,
}

#[derive(clap::Args)]
struct BgpArgs {
    /// Only announce addresses on interfaces matching these globs
    #[arg(long = "include", value_name = "GLOB")]
    include: Vec<String>,
    /// Additional interface globs whose addresses are never announced
    #[arg(long = "exclude", value_name = "GLOB")]
    exclude: Vec<String>,
    /// Reject a default route learned from AWS
    #[arg(long)]
    no_default_route: bool,
    #[arg(long, default_value_t = 4)]
    maximum_paths: u8,
    #[arg(long, default_value = "/usr/lib/frr/frr-reload.py")]
    frr_reload: String,
    /// FRR vty socket directory, for a non-default FRR instance
    #[arg(long)]
    vty_socket: Option<String>,
    /// Seconds between discovery passes (each pass calls the EC2 API)
    #[arg(long, default_value_t = 15.0)]
    interval: f64,
    #[arg(long, default_value = "127.0.0.1")]
    listen: std::net::IpAddr,
    #[arg(long, default_value_t = 9811)]
    port: u16,
    #[arg(long, default_value = "/var/lib/route-discovery-bgp")]
    state_dir: PathBuf,
    /// Create tunnels and reload bgpd (default is dry-run)
    #[arg(long)]
    apply: bool,
    /// Create this instance's VPC Route Server peers on endpoints in its subnets
    #[arg(long)]
    register: bool,
    /// Local ASN for self-registered peers; must differ from the route server's ASN
    #[arg(long, default_value_t = 65001, requires = "register")]
    register_asn: u32,
    /// Liveness detection for self-registered peers
    #[arg(long, value_enum, default_value_t = Liveness::Bfd, requires = "register")]
    register_liveness: Liveness,
}

#[derive(Clone, Copy, ValueEnum)]
enum Liveness {
    Bfd,
    BgpKeepalive,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MeshOperation {
    /// Print the discovered NICs, published subnets and skipped interfaces
    Inventory,
    /// Print the babeld fragment derived from the inventory
    RenderFrr,
    /// Print the vtysh commands that would reconcile the running FRR
    Plan,
    /// Keep FRR babeld in step with the NIC inventory
    Run,
    /// Remove the mesh's babeld instance and filters
    Withdraw,
}

#[derive(clap::Args)]
struct MeshArgs {
    /// Only mesh interfaces matching these globs (replaces the default exclusions)
    #[arg(long = "include", value_name = "GLOB")]
    include: Vec<String>,
    /// Additional interface globs to keep out of the mesh
    #[arg(long = "exclude", value_name = "GLOB")]
    exclude: Vec<String>,
    /// Supernets accepted from and relayed to neighbours (default: RFC 1918, CGNAT, ULA)
    #[arg(long = "accept", value_name = "PREFIX")]
    accept: Vec<String>,
    #[arg(long, default_value_t = 1000)]
    hello_interval_ms: u32,
    #[arg(long, default_value_t = 4000)]
    update_interval_ms: u32,
    /// FRR vty socket directory, for a non-default FRR instance
    #[arg(long)]
    vty_socket: Option<String>,
    /// Seconds between inventory/reconcile passes
    #[arg(long, default_value_t = 2.0)]
    interval: f64,
    #[arg(long, default_value = "127.0.0.1")]
    listen: std::net::IpAddr,
    #[arg(long, default_value_t = 9810)]
    port: u16,
    #[arg(long, default_value = "/var/lib/route-discovery-mesh")]
    state_dir: PathBuf,
    /// Write FRR configuration (default is dry-run)
    #[arg(long)]
    apply: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ServerOperation {
    Validate,
    RenderFrr,
    Run,
    Demo,
    Withdraw,
}

async fn run_daemon(config: Config, apply: bool) -> Result<()> {
    // Dry runs have a separate lock/checkpoint; they cannot reset live dampening state.
    let directory = if apply { config.state_dir.clone() } else { config.state_dir.join("dry-run") };
    let mut store = StateStore::new(directory);
    store.acquire()?;
    let backend = make_backend(&config, apply).await?;
    let daemon = Arc::new(Daemon::new(config, backend).with_store(store).with_apply(apply));
    server::stop_on_signals(daemon.stop.clone())?;
    daemon.run().await
}

/// systemd ExecStopPost also runs after SIGKILL/watchdog failures.
async fn cleanup(config: Config) -> Result<()> {
    if config.backend.kind != BackendKind::Frr {
        return Ok(());
    }
    let mut store = StateStore::new(&config.state_dir);
    store.acquire()?;
    let backend = make_backend(&config, true).await?;
    for route in &config.routes {
        if !backend.apply(route, &Decision::new(Action::Withdraw, "supervisor cleanup")).await? {
            return Err(Error::Backend(format!("FRR withdrawal did not converge: {}", route.prefix)));
        }
    }
    Ok(())
}

fn bgp_options(args: BgpArgs) -> Result<bgp::Options> {
    if !(args.interval.is_finite() && args.interval >= 5.0) {
        return config_err("--interval must be at least 5 seconds to stay within EC2 API rate limits");
    }
    // 0 and AS_TRANS (23456) are not valid speaker ASNs.
    if args.register && matches!(args.register_asn, 0 | 23456) {
        return config_err("--register-asn must be a valid BGP ASN");
    }
    if !(1..=64).contains(&args.maximum_paths) {
        return config_err("--maximum-paths must be 1-64");
    }
    let mut filter = Filter { include: args.include, ..bgp::advertise::default_filter() };
    filter.exclude.extend(args.exclude);
    Ok(bgp::Options {
        filter,
        policy: bgp::frr::Policy { accept_default: !args.no_default_route, maximum_paths: args.maximum_paths },
        frr_reload: args.frr_reload,
        vty_socket: args.vty_socket,
        interval: args.interval,
        listen: args.listen,
        port: args.port,
        state_dir: args.state_dir,
        apply: args.apply,
        register: args.register.then(|| bgp::registration::Registration {
            asn: args.register_asn,
            liveness: match args.register_liveness {
                Liveness::Bfd => "bfd",
                Liveness::BgpKeepalive => "bgp-keepalive",
            }
            .into(),
        }),
    })
}

async fn bgp_command(operation: BgpOperation, args: BgpArgs) -> Result<()> {
    let options = bgp_options(args)?;
    if operation == BgpOperation::Run {
        return bgp::run(options).await;
    }
    if operation == BgpOperation::Withdraw && !options.apply {
        return config_err("bgp withdraw requires --apply");
    }
    // Plan and withdraw write bgpd.conf in the state directory; discovery only reads.
    let mut store = StateStore::new(&options.state_dir);
    if matches!(operation, BgpOperation::Plan | BgpOperation::Withdraw) {
        store.acquire()?;
    }
    let controller = bgp::system(options).await?;
    match operation {
        BgpOperation::Discover => {
            let observation = controller.observe().await?;
            println!("{}", serde_json::to_string_pretty(&observation).unwrap_or_default());
        }
        BgpOperation::RenderFrr => print!("{}", controller.observe().await?.config),
        BgpOperation::Plan => {
            let observation = controller.observe().await?;
            for command in &observation.tunnel_commands {
                println!("{}", command.join(" "));
            }
            print!("{}", controller.diff(&observation.config).await?);
        }
        BgpOperation::Withdraw => bgp::withdraw(&controller).await?,
        BgpOperation::Run => unreachable!(),
    }
    Ok(())
}

fn mesh_options(args: MeshArgs) -> Result<mesh::Options> {
    let mut filter = Filter { include: args.include, ..Filter::default() };
    filter.exclude.extend(args.exclude);
    let mut policy =
        Policy { hello_interval_ms: args.hello_interval_ms, update_interval_ms: args.update_interval_ms, ..Policy::default() };
    if !args.accept.is_empty() {
        policy.accept = args
            .accept
            .iter()
            .map(|p| {
                p.parse::<ipnet::IpNet>().map(|n| n.trunc()).map_err(|_| Error::Config(format!("invalid --accept prefix {p}")))
            })
            .collect::<Result<_>>()?;
    }
    if policy.accept.iter().any(|n| n.prefix_len() == 0) {
        return config_err("--accept must not include a default route; the mesh never carries one");
    }
    if !(10..=65_535).contains(&policy.hello_interval_ms) || policy.update_interval_ms < policy.hello_interval_ms {
        return config_err("hello interval must be 10-65535 ms and no greater than the update interval");
    }
    if !(args.interval.is_finite() && args.interval >= 0.2) {
        return config_err("--interval must be at least 0.2 seconds");
    }
    Ok(mesh::Options {
        filter,
        policy,
        socket_dir: args.vty_socket,
        interval: args.interval,
        listen: args.listen,
        port: args.port,
        state_dir: args.state_dir,
        apply: args.apply,
    })
}

async fn mesh_command(operation: MeshOperation, args: MeshArgs) -> Result<()> {
    let options = mesh_options(args)?;
    let vtysh = Vtysh { runner: &SystemRunner, socket_dir: options.socket_dir.as_deref() };
    match operation {
        MeshOperation::Inventory => {
            let inventory = collect(&SystemRunner, &options.filter).await?;
            println!("{}", serde_json::to_string_pretty(&inventory).unwrap_or_default());
        }
        MeshOperation::RenderFrr => {
            let inventory = collect(&SystemRunner, &options.filter).await?;
            print!("{}", mesh::frr::render(&mesh::frr::desired(&inventory, &options.policy)));
        }
        MeshOperation::Plan => {
            let inventory = collect(&SystemRunner, &options.filter).await?;
            let desired = mesh::frr::desired(&inventory, &options.policy);
            for command in mesh::frr::plan(&desired, &vtysh.running().await?) {
                println!("{command}");
            }
        }
        MeshOperation::Run => mesh::run(options).await?,
        MeshOperation::Withdraw if !options.apply => return config_err("mesh withdraw requires --apply"),
        MeshOperation::Withdraw => mesh::withdraw(options.socket_dir.as_deref()).await?,
    }
    Ok(())
}

async fn server_command(
    operation: ServerOperation,
    config: Option<PathBuf>,
    endpoint: Option<String>,
    apply: bool,
) -> Result<()> {
    if operation == ServerOperation::Demo {
        return server::demo::demo().await;
    }
    let Some(path) = config else { return config_err("server operation requires --config") };
    let config = server::config::load(path)?;
    match operation {
        ServerOperation::Validate => println!(
            "Valid route server {}: {} endpoints, {} peers, {} propagations",
            config.id,
            config.endpoints.len(),
            config.peers.len(),
            config.propagations.len()
        ),
        ServerOperation::RenderFrr => {
            let Some(endpoint) = endpoint else { return config_err("render-frr requires --endpoint") };
            print!("{}", server::frr::render(&config, &endpoint)?);
        }
        ServerOperation::Withdraw if !apply => {
            return config_err("server withdraw requires --apply and an existing ownership journal");
        }
        ServerOperation::Run | ServerOperation::Withdraw => {
            server::run(config, apply, operation == ServerOperation::Withdraw).await?;
        }
        ServerOperation::Demo => unreachable!(),
    }
    Ok(())
}

async fn execute(command: Command) -> Result<()> {
    match command {
        Command::Bgp { operation, args } => bgp_command(operation, args).await,
        Command::Mesh { operation, args } => mesh_command(operation, args).await,
        Command::Server { operation, config, endpoint, apply } => server_command(operation, config, endpoint, apply).await,
        Command::Demo => {
            route_discovery::demo::run_demo();
            Ok(())
        }
        Command::Status { url } => {
            let body = route_discovery::http::get(&url).await?;
            let value: serde_json::Value = serde_json::from_str(&body).map_err(|e| Error::Backend(e.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
            Ok(())
        }
        Command::Validate { config } => {
            let config = load(config)?;
            let paths: usize = config.routes.iter().map(|r| r.candidates.len()).sum();
            println!("Valid: {} prefixes, {paths} paths, backend={}", config.routes.len(), config.backend.kind.as_str());
            Ok(())
        }
        Command::ProbePlan { config } => {
            print!("{}", probe_plan(&load(config)?)?);
            Ok(())
        }
        Command::CheckPaths { config } => {
            let config = load(config)?;
            validate_probe_paths(&config, &SystemRunner).await?;
            if config.backend.kind == BackendKind::Aws {
                println!("AWS external probe paths require validation at their vantage points");
            } else {
                println!("Probe routing checks passed");
            }
            Ok(())
        }
        Command::RenderFrr { config, router_id, peer, peer_asn, med } => {
            print!("{}", frr_config(&load(config)?, &router_id, &peer, peer_asn, med)?);
            Ok(())
        }
        Command::Run { config, apply } => run_daemon(load(config)?, apply).await,
        Command::CleanupFrr { config, apply } => {
            if !apply {
                return config_err("cleanup-frr requires --apply");
            }
            cleanup(load(config)?).await
        }
    }
}

fn main() -> ExitCode {
    // Behave like a normal CLI when piped into `head`: exit quietly on a closed pipe.
    // SAFETY: called before any threads exist; SIG_DFL is a valid disposition.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    let level = match cli.log_level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warning => "warn",
        LogLevel::Error => "error",
    };
    tracing_subscriber::fmt()
        .with_env_filter(level)
        .with_target(false)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("route-discovery: {e}");
            return ExitCode::from(2);
        }
    };
    match runtime.block_on(execute(cli.command)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("route-discovery: {e}");
            ExitCode::from(2)
        }
    }
}
