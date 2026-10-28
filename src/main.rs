use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};

use route_discovery::backends::{make_backend, probe_plan, validate_probe_paths};
use route_discovery::commands::SystemRunner;
use route_discovery::config::{load, BackendKind, Config};
use route_discovery::daemon::Daemon;
use route_discovery::error::{config_err, Error, Result};
use route_discovery::frr_export::frr_config;
use route_discovery::policy::{Action, Decision};
use route_discovery::server;
use route_discovery::state::StateStore;

#[derive(Parser)]
#[command(name = "route-discovery", version, about = "Health-driven Linux/AWS routing, with FRR BGP integration")]
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
