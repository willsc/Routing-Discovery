use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use route_discovery::bgp;
use route_discovery::commands::SystemRunner;
use route_discovery::dx;
use route_discovery::error::{config_err, Error, Result};
use route_discovery::mesh::{self, frr::Policy, frr::Vtysh, inventory::Filter, inventory::DEFAULT_EXCLUDE};
use route_discovery::state::StateStore;

#[derive(Parser)]
#[command(name = "route-discovery", version, about = "Zero-configuration routing: discover peers and prefixes, drive FRR")]
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
    /// EC2 instance: BGP to VPC Route Server and Transit Gateway Connect
    Bgp {
        operation: BgpOperation,
        #[command(flatten)]
        args: BgpArgs,
    },
    /// Host outside AWS terminating Direct Connect VIFs: BGP over private and transit VIFs
    Dx {
        operation: DxOperation,
        #[command(flatten)]
        args: DxArgs,
    },
    /// Every host: Babel mesh over its NICs and, with --registry or --peers-file, GRE tunnels to other sites
    Mesh {
        operation: MeshOperation,
        #[command(flatten)]
        args: MeshArgs,
    },
    /// Print a running controller's status
    Status {
        #[arg(long, default_value = "http://127.0.0.1:9811/status")]
        url: String,
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
    /// Delete tagged Route Server peers in this VPC whose owner instance has terminated
    #[arg(long)]
    sweep: bool,
    /// Local ASN for self-registered peers; must differ from the route server's ASN
    #[arg(long, default_value_t = 65001, requires = "register")]
    register_asn: u32,
    /// Liveness detection for self-registered peers
    #[arg(long, value_enum, default_value_t = Liveness::Bfd, requires = "register")]
    register_liveness: Liveness,
}

#[derive(Clone, Copy, ValueEnum)]
enum Platform {
    Auto,
    Ec2,
    Metal,
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
#[command(group = clap::ArgGroup::new("overlay").args(["registry", "peers_file"]))]
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
    /// Shared host registry (s3://bucket/prefix); enables GRE tunnels between sites
    #[arg(long, value_name = "S3_URL")]
    registry: Option<String>,
    /// Static JSON list of hosts, instead of --registry; re-read every --registry-interval
    #[arg(long, value_name = "PATH")]
    peers_file: Option<PathBuf>,
    /// The registry bucket's region (default from the AWS configuration chain)
    #[arg(long, requires = "registry", conflicts_with = "peers_file")]
    registry_region: Option<String>,
    /// Where this host runs; auto asks IMDS
    #[arg(long, value_enum, default_value_t = Platform::Auto, requires = "overlay")]
    platform: Platform,
    /// Site this host belongs to (default: its VPC on EC2, the host itself elsewhere); with --peers-file, the file sets it
    #[arg(long, requires = "registry", conflicts_with = "peers_file")]
    site: Option<String>,
    /// Underlay IPv4 address other hosts tunnel to (default: primary IPv4 on EC2, default-path source elsewhere)
    #[arg(long, requires = "overlay")]
    endpoint: Option<std::net::Ipv4Addr>,
    /// Relays per site
    #[arg(long, default_value_t = 2, requires = "overlay")]
    relays: usize,
    /// Seconds between registry syncs (each is an S3 PUT and LIST) or peers-file reads
    #[arg(long, default_value_t = 60.0, requires = "overlay")]
    registry_interval: f64,
    /// Tunnel MTU; the default fits a 1500-byte underlay such as inter-region peering
    #[arg(long, default_value_t = 1476, requires = "overlay")]
    tunnel_mtu: u32,
    /// Write FRR configuration (default is dry-run)
    #[arg(long)]
    apply: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DxOperation {
    /// Print this router's VIFs, VLAN links and announced prefixes (JSON)
    Discover,
    /// Print the bgpd configuration derived from discovery (includes MD5 keys)
    RenderFrr,
    /// Print VLAN commands and the bgpd changes a reload would make
    Plan,
    /// Keep VLAN links and bgpd in step with Direct Connect and local interfaces
    Run,
    /// Remove the VIF sessions and owned VLAN links
    Withdraw,
}

#[derive(clap::Args)]
struct DxArgs {
    /// Region to read VIFs from (repeatable; default from the AWS configuration chain)
    #[arg(long = "region", value_name = "REGION")]
    regions: Vec<String>,
    /// Provision VLAN links for a connection or LAG's VIFs on a parent interface
    #[arg(long = "parent", value_name = "IFACE=DXCON")]
    parents: Vec<String>,
    /// Only announce subnets on interfaces matching these globs
    #[arg(long = "include", value_name = "GLOB")]
    include: Vec<String>,
    /// Additional interface globs whose subnets are never announced
    #[arg(long = "exclude", value_name = "GLOB")]
    exclude: Vec<String>,
    /// Extra prefix to announce, such as an on-prem aggregate present in the RIB (repeatable)
    #[arg(long = "announce", value_name = "PREFIX")]
    announce: Vec<String>,
    /// Accept a default route from AWS
    #[arg(long)]
    accept_default_route: bool,
    /// Do not enable BFD on VIF sessions
    #[arg(long)]
    no_bfd: bool,
    #[arg(long, default_value_t = 4)]
    maximum_paths: u8,
    #[arg(long, default_value = "/usr/lib/frr/frr-reload.py")]
    frr_reload: String,
    #[arg(long)]
    vty_socket: Option<String>,
    /// Seconds between discovery passes (each pass calls the Direct Connect API)
    #[arg(long, default_value_t = 30.0)]
    interval: f64,
    #[arg(long, default_value = "127.0.0.1")]
    listen: std::net::IpAddr,
    #[arg(long, default_value_t = 9812)]
    port: u16,
    #[arg(long, default_value = "/var/lib/route-discovery-dx")]
    state_dir: PathBuf,
    /// Create VLAN links and reload bgpd (default is dry-run)
    #[arg(long)]
    apply: bool,
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
        sweep: args.sweep,
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
    let source = match (args.registry, args.peers_file) {
        (Some(url), _) => {
            mesh::overlay::registry::parse_url(&url)?;
            Some(mesh::overlay::Source::Registry { url, region: args.registry_region })
        }
        (None, Some(path)) => Some(mesh::overlay::Source::File(path)),
        (None, None) => None,
    };
    let overlay = match source {
        None => None,
        Some(source) => {
            if !(1..=8).contains(&args.relays) {
                return config_err("--relays must be 1-8");
            }
            if !(args.registry_interval.is_finite() && args.registry_interval >= 10.0) {
                return config_err("--registry-interval must be at least 10 seconds");
            }
            // Babel needs IPv6 link-local on each tunnel, so the IPv6 minimum applies.
            if !(1280..=8977).contains(&args.tunnel_mtu) {
                return config_err("--tunnel-mtu must be 1280-8977");
            }
            Some(mesh::overlay::Options {
                source,
                platform: match args.platform {
                    Platform::Auto => mesh::overlay::PlatformChoice::Auto,
                    Platform::Ec2 => mesh::overlay::PlatformChoice::Ec2,
                    Platform::Metal => mesh::overlay::PlatformChoice::Metal,
                },
                site: args.site,
                endpoint: args.endpoint,
                relays: args.relays,
                interval: args.registry_interval,
                mtu: args.tunnel_mtu,
            })
        }
    };
    Ok(mesh::Options {
        overlay,
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
    if !matches!(operation, MeshOperation::Inventory | MeshOperation::RenderFrr | MeshOperation::Plan) {
        return match operation {
            MeshOperation::Withdraw if !options.apply => config_err("mesh withdraw requires --apply"),
            MeshOperation::Withdraw => mesh::withdraw(options.socket_dir.as_deref()).await,
            _ => mesh::run(options).await,
        };
    }
    // Previews never apply: the overlay reads the registry without publishing and changes nothing.
    let mut preview = mesh::Mesh::new(mesh::Options { apply: false, ..options.clone() }, std::sync::Arc::new(SystemRunner));
    if let Some(overlay) = options.overlay.clone() {
        preview = preview.with_overlay(mesh::overlay::system(overlay, &SystemRunner).await?);
    }
    let (inventory, desired, overlay_commands) = preview.preview().await?;
    match operation {
        MeshOperation::Inventory => {
            let mut value = serde_json::to_value(&inventory).unwrap_or_default();
            if let Some(overlay) = preview.overlay_snapshot() {
                value["overlay"] = overlay;
            }
            println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
        }
        MeshOperation::RenderFrr => print!("{}", mesh::frr::render(&desired)),
        MeshOperation::Plan => {
            for command in overlay_commands {
                println!("{command}");
            }
            for command in mesh::frr::plan(&desired, &vtysh.running().await?) {
                println!("{command}");
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn dx_options(args: DxArgs) -> Result<dx::Options> {
    if !(args.interval.is_finite() && args.interval >= 10.0) {
        return config_err("--interval must be at least 10 seconds to stay within Direct Connect API rate limits");
    }
    if !(1..=64).contains(&args.maximum_paths) {
        return config_err("--maximum-paths must be 1-64");
    }
    let mut ports = BTreeMap::new();
    for port in &args.parents {
        let Some((interface, connection)) = port.split_once('=').filter(|(i, c)| !i.is_empty() && !c.is_empty()) else {
            return config_err(format!("--parent {port}: expected IFACE=dxcon-... or IFACE=dxlag-..."));
        };
        if !(connection.starts_with("dxcon-") || connection.starts_with("dxlag-")) {
            return config_err(format!("--parent {port}: {connection} is not a connection or LAG ID"));
        }
        if ports.insert(connection.to_string(), interface.to_string()).is_some() {
            return config_err(format!("--parent: {connection} mapped twice"));
        }
    }
    let announce = args
        .announce
        .iter()
        .map(|p| p.parse::<ipnet::IpNet>().map_err(|_| Error::Config(format!("invalid --announce prefix {p}"))))
        .collect::<Result<Vec<_>>>()?;
    if announce.iter().any(|n| n.prefix_len() == 0) {
        return config_err("--announce must not include a default route");
    }
    let mut filter = Filter { include: args.include, exclude: DEFAULT_EXCLUDE.iter().map(|s| s.to_string()).collect() };
    filter.exclude.extend(args.exclude);
    Ok(dx::Options {
        regions: args.regions,
        ports,
        filter,
        announce,
        policy: dx::frr::Policy {
            bfd: !args.no_bfd,
            accept_default: args.accept_default_route,
            maximum_paths: args.maximum_paths,
        },
        frr_reload: args.frr_reload,
        vty_socket: args.vty_socket,
        interval: args.interval,
        listen: args.listen,
        port: args.port,
        state_dir: args.state_dir,
        apply: args.apply,
    })
}

async fn dx_command(operation: DxOperation, args: DxArgs) -> Result<()> {
    let options = dx_options(args)?;
    if operation == DxOperation::Run {
        return dx::run(options).await;
    }
    if operation == DxOperation::Withdraw && !options.apply {
        return config_err("dx withdraw requires --apply");
    }
    // Plan and withdraw write bgpd.conf in the state directory; discovery only reads.
    let mut store = StateStore::new(&options.state_dir);
    if matches!(operation, DxOperation::Plan | DxOperation::Withdraw) {
        store.acquire()?;
    }
    let controller = dx::system(options).await?;
    match operation {
        DxOperation::Discover => {
            let observation = controller.observe().await?;
            println!("{}", serde_json::to_string_pretty(&observation).unwrap_or_default());
        }
        DxOperation::RenderFrr => print!("{}", controller.observe().await?.config),
        DxOperation::Plan => {
            let observation = controller.observe().await?;
            for command in &observation.link_commands {
                println!("{}", command.join(" "));
            }
            print!("{}", controller.diff(&observation.config).await?);
        }
        DxOperation::Withdraw => dx::withdraw(&controller).await?,
        DxOperation::Run => unreachable!(),
    }
    Ok(())
}

async fn execute(command: Command) -> Result<()> {
    match command {
        Command::Bgp { operation, args } => bgp_command(operation, args).await,
        Command::Dx { operation, args } => dx_command(operation, args).await,
        Command::Mesh { operation, args } => mesh_command(operation, args).await,
        Command::Status { url } => {
            let body = route_discovery::http::get(&url).await?;
            let value: serde_json::Value = serde_json::from_str(&body).map_err(|e| Error::Backend(e.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
            Ok(())
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

#[cfg(test)]
mod tests {
    #[test]
    fn cli_is_well_formed() {
        use clap::CommandFactory;
        super::Cli::command().debug_assert();
    }
}
