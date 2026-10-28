# route-discovery

A Linux daemon that monitors independently routed paths to destination prefixes, switches traffic to healthy alternatives, and returns to the preferred path after stable recovery. It provides BGP-style local policy and can hand selected routes to **FRR for real BGP and BFD**.

Implemented in Rust as a single static-ish binary (`route-discovery`) built on Tokio. The AWS backend uses the official AWS SDK for Rust behind the default `aws` Cargo feature; build with `--no-default-features` for a Linux/FRR-only binary. This is an initial implementation with local integration tests; AWS deployment and live FRR peering still require staging validation.

Version 0.2 also includes a **BGP-to-VPC route-server mode**: learn paths dynamically from multiple FRR endpoints/peers, compute a RIB/FIB, and propagate selections into multiple AWS route tables with durable ownership and withdrawal tracking. See [the route-server guide](docs/route-server.md) and [example configuration](examples/route-server.toml). Try `route-discovery server demo`. The modes below remain available for appliance and host health-driven routing.

**Zero-configuration BGP to AWS** (`route-discovery bgp run --apply`) needs no configuration file either. It reads the instance from IMDS and finds the VPC Route Server and Transit Gateway Connect peers that name its ENIs. It builds the Connect GRE tunnels and announces the instance's service VIPs through FRR bgpd. AWS then carries the routes to VPC route tables, other VPCs, VPN and Direct Connect. See [the BGP guide](docs/bgp.md).

**Zero-configuration mesh** (`route-discovery mesh run --apply`) needs no configuration file. It discovers every eligible NIC, publishes the host's connected subnets through FRR babeld, and lets Babel build a self-healing multipath mesh between hosts. Container and bridge subnets are withheld automatically. Run `route-discovery mesh inventory` to see what a host would publish. See [the mesh guide](docs/mesh.md), including its security and cloud-overlay caveats.

## Choose the routing plane

| Backend | What changes | Best fit |
| --- | --- | --- |
| `linux` | Explicitly owned routes in one Linux routing table | EC2 host routing through independent tunnels/interfaces |
| `frr` | Tagged static routes in FRR, redistributed into BGP | Appliance routing with real BGP peers, including AWS VPC Route Server |
| `aws` | One ENI target per destination in one VPC route table | Installations using EC2 APIs instead of BGP |

For AWS appliances requiring BGP/BFD behavior, use the **FRR backend with VPC Route Server**. AWS documents BFD failure detection and propagation of selected BGP routes into VPC route tables. The daemon adds destination health checks beyond peer liveness. [AWS Route Server operation](https://docs.aws.amazon.com/vpc/latest/userguide/route-server-how-it-works.html).

The daemon does not implement the BGP or BFD wire protocols. FRR handles sessions, learned route policy, loop prevention, communities and protocol timers. The local daemon selects from **configured** paths; its `as_path` values are policy inputs, not learned BGP attributes. No service claims subsecond or lossless convergence. Direct EC2 API updates have control-plane latency and throttling.

## Routing behavior

- Concurrent TCP connect checks for every path, including inactive paths; multiple endpoints and a configurable success quorum.
- Consecutive failure/recovery thresholds, stale-probe expiry and configurable failback delay. Emergency failover bypasses elective failback delay.
- Deterministic ranking: higher local preference, shorter configured AS path, lower MED, lower cost, then existing path and candidate ID. MED is always compared across paths; this intentionally differs from full BGP best-path selection.
- Configured paths containing the local ASN are ineligible. `enabled = false` excludes a path. Only explicit prefixes and next hops can be managed.
- Equal-ranked paths can use ECMP on Linux/FRR. Linux IPv6 ECMP needs explicit gateways. AWS route tables have a single selected target.
- Flap penalties, exponential decay, suppression/reuse thresholds and a maximum suppression period. Dampening survives restart; health is always freshly measured.
- Live state inspection, ownership checks, idempotent reconciliation, bounded subprocesses, SDK timeouts and retry backoff. Failed writes never become successful routing decisions.
- Read-only status/Prometheus endpoints, systemd watchdog support, per-process locking and default dry-run operation.

## Try it without changing routes

From this directory:

```sh
cargo run -- demo
cargo run -- validate -c examples/linux.toml
cargo test
```

The demo prints initial primary selection, backup selection when the primary fails, and restoration after its hold-down. The test suite also opens real local TCP listeners, stops/restarts a listener and checks the daemon's complete failover/failback cycle with an in-memory routing backend.

For a normal installation (Rust 1.89+):

```sh
cargo build --release
sudo install -m 0755 target/release/route-discovery /usr/local/bin/
# Linux/FRR only, without the AWS SDK:
cargo build --release --no-default-features
```

## Configure Linux routing

Start from [examples/linux.toml](examples/linux.toml). Replace the destination, interfaces and probe endpoints. The example assumes two independently working WireGuard tunnels, `wg-a` and `wg-b`; provisioning those tunnels is outside the daemon. WireGuard must allow the destination on each relevant peer and must not separately install competing routes for the managed prefix (for example, use `Table = off` when appropriate).

**A probe must traverse its candidate path even while that path is inactive.** Binding a socket to an interface alone is insufficient when paths share an interface. The Linux and FRR modes require a packet mark for each candidate and use dedicated probe tables. The table ID and rule priority equal that mark (1000–30000). Each table gets host routes for its probe endpoints and an `unreachable default` to prevent fallback to the active route.

```sh
route-discovery probe-plan -c examples/linux.toml > /tmp/probe-routes.sh
# Inspect existing policy rules/tables and the generated file before provisioning.
ip rule show
ip route show table all
cat /tmp/probe-routes.sh
# After adjusting your configuration and reserving the listed tables/priorities:
sudo sh /tmp/probe-routes.sh
sudo route-discovery check-paths -c examples/linux.toml
```

The generated script changes only probe routing, but it still needs review: table IDs/rule priorities must be reserved, and rerunning `ip rule add` can create duplicate rules on Linux. Do not run it repeatedly without reconciling existing rules. Marked traffic must not be overridden by earlier policy rules. The daemon checks the effective marked route and terminal default at startup and before every live probe sample; invalid isolation makes the candidate unhealthy. This detects configuration drift but is not an atomic guarantee against a concurrent routing administrator.

TCP probes test connection establishment, not application correctness or arbitrary packet sizes. Use endpoints beyond the forwarding appliance and representative of the destination. A management-port check only establishes that the appliance is alive. Check return routing, tunnel MTU, security groups, NACLs and reverse-path filtering. There is no automatic `rp_filter` or firewall modification.

Start in dry-run mode, setting `daemon.state_dir` to a writable absolute directory if necessary:

```sh
sudo route-discovery run -c examples/linux.toml
```

Dry-run uses an in-memory route table and does not load AWS credentials, read the live FIB or write routes. It still sends the configured probes and needs the privileges/path setup required by those probes. Its checkpoint and lock live in a separate `dry-run` directory. To make live route changes, use `run ... --apply` after provisioning and checking the configuration.

Linux routes are owned by the configured numeric protocol and metric (defaults `196`/`100`). A conflicting route for the same prefix causes an error; it is never automatically adopted or overwritten. The reserved BGP protocol `186` is rejected. Use a dedicated Linux table plus your own policy rules if you need separation from routes managed by another system. No policy rule for the **traffic** table is installed by this daemon.

EC2 VPC networking does not make arbitrary remote EC2 private addresses usable as ordinary Ethernet next hops. Use a valid tunnel/overlay topology for host routing, or AWS-supported ENI targets/VPC Route Server for VPC routing. For appliances, AWS requires source/destination checking to be disabled and describes subnet and return-path constraints. [AWS appliance routing guidance](https://docs.aws.amazon.com/vpc/latest/userguide/route-table-options.html).

## Real BGP with FRR

Use [examples/frr.toml](examples/frr.toml) and provision its marked probe tables as above. Install FRR separately and enable `zebra`, `staticd`, `bgpd` and `bfdd`. Generate a policy fragment:

```sh
route-discovery render-frr -c examples/frr.toml \
  --router-id 10.0.1.10 --peer 10.0.1.20 --peer-asn 64512 --med 100
```

Merge the output into the appliance's FRR configuration after replacing the example IDs. It limits redistribution to the configured prefixes and reserved route tag, applies an export prefix filter, enables BFD for the neighbor, and denies inbound advertisements by default. Add deliberately scoped inbound policy if the appliance needs learned routes. Configure both route-server endpoints where required; the generator emits one peer, not a complete redundant AWS deployment. The MED argument is an appliance-wide export preference; local candidate attributes are not automatically exported as BGP attributes.

The daemon adds/removes tagged static routes using `vtysh`; FRR redistributes eligible statics. It adds replacement paths before removing old ones, so a transition can briefly use ECMP. Reconciliation verifies FRR's running static configuration, **not** kernel installation, BGP establishment or remote FIB convergence. Verify those separately with FRR operational commands. [FRR static routing](https://docs.frrouting.org/en/latest/static.html), [BGP redistribution](https://docs.frrouting.org/en/latest/bgp.html#redistribution).

Do not save health-dependent runtime statics with `write memory`. Reserve the route tag and `RD-*` policy names. Run a single writer per FRR instance. On orderly shutdown the daemon withdraws its statics. The provided service also runs ownership-checked `cleanup-frr --apply` after crashes/watchdog termination. FRR availability is required for cleanup; alert on cleanup failures. A whole-appliance failure is handled by the peer's BFD session. Running the daemon without supervision cannot guarantee withdrawal after SIGKILL.

## Direct AWS API backend

Use [examples/aws.toml](examples/aws.toml), real ENI IDs and one explicitly tagged VPC route table. The daemon supports IPv4/IPv6 prefixes, `CreateRoute`, `ReplaceRoute` and `DeleteRoute`, using the AWS credential chain. Prefer an instance role; do not put credentials in TOML.

Adapt [deploy/aws-policy.json](deploy/aws-policy.json) to your account, region and route table. It scopes writes to that table and ownership tag. It does not grant infrastructure creation or tagging. Local/propagated routes and targets outside the configured ENI allowlist are rejected. Readback must show the desired active target before success is reported. [EC2 route API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceRoute.html), [EC2 IAM actions and conditions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html).

Each candidate requires `external_path`, documenting an independently routed probe endpoint or vantage point. This is an operator assertion, not automatic AWS path discovery. Probing the same destination through the currently selected VPC table cannot identify individual candidate health. Provision distinct, fixed paths to representative endpoints before enabling this backend; a local socket mark cannot choose an arbitrary AWS ENI route target.

**Run exactly one active AWS writer.** The local lock prevents duplicate processes only when they share a state directory. It is not a distributed lease, and EC2 route changes provide no compare-and-swap fencing. Do not run competing daemons, Terraform route resources or another controller for these prefixes. For redundant control planes, use FRR/VPC Route Server rather than assuming this API backend implements leader election.

## Failure and shutdown policy

| `all_down` | Behavior |
| --- | --- |
| `withdraw` | Remove the managed route; less-specific routes may then carry traffic. FRR withdraws its static contribution to BGP. |
| `retain` | Keep the current route, report degraded readiness; useful when withdrawal would create an unwanted fallback. |
| `unreachable` | Linux only: install a terminal unreachable route to stop default-route leakage. |

On restart, existing owned routes are observed and initial health is assessed before all-down handling. Recovery hold-down applies when a healthy current path exists. Linux and AWS routes remain on daemon shutdown, so a restart does not abruptly remove working routes. They also remain after a crash until a supervisor restarts the daemon; the watchdog bounds hangs when deployed with systemd. Connection state/NAT sessions are not replicated, so existing sessions may break during failover.

Configuration is immutable during a run. Validate changes, then restart. Before removing a prefix or changing its ownership fields, explicitly retire the old owned routes using the old configuration; removing it from TOML does not delete an untracked route. FRR cleanup should use the old config before replacement. Probe tables/rules are operator-managed and remain after shutdown.

## Install as a service

Create a dedicated `route-discovery` system user, install the binary at `/usr/local/bin/route-discovery`, and put your validated configuration at `/etc/route-discovery/config.toml`. Install [deploy/route-discovery.service](deploy/route-discovery.service) into systemd and provision the probe routes before starting it. The unit is configured for **live writes** and includes restart/watchdog supervision. It grants `CAP_NET_ADMIN`/`CAP_NET_RAW` for local route/probe operations.

For FRR, add a systemd drop-in with `After=frr.service`, `Requires=frr.service` under `[Unit]` and `SupplementaryGroups=frrvty` under `[Service]` (verify your distribution's socket group). For AWS-only use without marked/device-bound probes, remove the network capabilities. The process needs network access to AWS APIs and, when using an instance role, IMDS. Do not use `PrivateNetwork=true`.

Status is bound to loopback by default and is unauthenticated/read-only:

```sh
route-discovery status
curl http://127.0.0.1:9808/metrics
curl http://127.0.0.1:9808/readyz
```

`/healthz` reports loop liveness; `/readyz` returns 503 if a prefix lacks a verified healthy selection or a backend has not converged. `/status` includes path health, sample age, penalties, desired/observed routing state and errors. Metrics expose eligibility, selected paths, penalties, changes and write errors. For FRR, readiness reflects verified static configuration only. Dry-run readiness reflects the simulated FIB and is labelled `mode: dry-run`. Keep the endpoint private or put authenticated access in front of it.

## Validation

```sh
make test         # cargo test: unit, contract and real-socket daemon tests
make validate
make demo
make kernel-test  # real iproute2 in a private namespace
make frr-test     # real FRR bgpd in a private namespace; FRR_ROOT=/extracted/frr for an unpacked package
make lint
```

State files are format-compatible with the earlier Python implementation: an existing `dampening.json` checkpoint and `route-server.sqlite3` ownership journal are read as-is.

The kernel smoke test uses `unshare` to create a **private user and network namespace**, creates dummy interfaces there, and exercises real IPv4/IPv6 route installation, failover, ECMP, unreachable routes, withdrawal and marked probe routing. It refuses to run in the parent network namespace. It needs user namespaces/netlink support; it does not change host or AWS routes.

The AWS and FRR adapters have contract/failure tests with fake services. Live AWS failover, real FRR sessions/BFD, production load, convergence timing and connection survival are not certified by these tests. See [the design and staging checklist](docs/design.md) before deployment.
