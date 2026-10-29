# route-discovery

Zero-configuration routing for hosts in AWS and outside it. There are no routing configuration files and no edge router. Every host runs the daemon: it discovers its interfaces, addresses and peers from the host, from AWS and from a shared S3 registry (or a peers file you distribute), then drives [FRR](https://frrouting.org), which speaks Babel, BGP and BFD. Hosts build GRE tunnels to each other across VPC peering, Direct Connect and leased lines and run Babel over them, so when a path fails, routing on the hosts reconfigures itself.

![How the overlay hangs together: who tunnels to whom, the registry and reconcile loops, how a packet leaves through a tunnel, and failover when a Direct Connect path fails](docs/images/overlay.svg)

To set up the registry and install the daemon on your hosts, see the [deployment runbook](docs/overlay-deployment.md).

| Role | Runs on | Discovers from | Speaks | Announces |
| --- | --- | --- | --- | --- |
| [`mesh`](docs/mesh.md) | Every host, EC2 or bare metal | Local NICs (`ip -json addr`); with `--registry`, IMDS and the [S3 registry](docs/overlay.md), or a static [peers file](docs/overlay.md#without-s3-a-peers-file) | Babel, over GRE tunnels between sites | EC2 relays: their VPC's CIDRs. Bare metal: connected subnets. Container and bridge subnets are withheld |
| [`bgp`](docs/bgp.md) | EC2 instances | IMDSv2; EC2 Route Server and TGW Connect peers that name its ENIs | BGP to VPC Route Server (with BFD) and TGW Connect (over GRE) | Service addresses outside the VPC CIDRs, such as VIPs on `lo` or `dummy` |
| [`dx`](docs/dx.md) | A host outside AWS that terminates Direct Connect VIFs itself | Direct Connect API: its private/transit VIFs, VLANs, peer addresses, ASNs, MD5 keys | BGP (with BFD) on every VIF | Its connected subnets and optional aggregates, capped at AWS's 100-prefix VIF limit |

Where carrier routers terminate Direct Connect, no host runs `dx`: the carrier carries the GRE tunnels' packets between bare-metal hosts and VPCs.

PrivateLink isn't a routing transport. Interface endpoints sit inside their VPC's CIDR and are reachable wherever that CIDR is routed. VPCs with overlapping CIDRs can't be joined by routing.

## How each role behaves

Every role runs the same loop:

1. **Discover:** read the host and AWS. This is read-only, every few seconds.
2. **Plan:** derive the FRR configuration and any interfaces the role needs: GRE tunnels between mesh hosts or to TGW Connect, VLAN links for DX VIFs.
3. **Apply,** only with `--apply`: create the interfaces, then reload FRR. Without `--apply`, every role is a dry run that logs what it would change.
4. **Verify and report:** BGP or Babel session state, announced and withheld prefixes, anything ignored and why. Results are served at `/status`, `/healthz`, `/readyz` and `/metrics`.

Safety rules shared by all roles:

- **Fail static.** If the controller stops, FRR keeps its sessions and routes. Withdrawal only happens on an explicit `withdraw --apply`.
- **Never black-hole.**
  - `bgp` withholds announcements while an ENI's source/destination check would drop the traffic.
  - `dx` announces nothing, rather than exceed AWS's prefix limit and idle the VIF.
  - `mesh` explicitly denies subnets on excluded interfaces.
- **Never learn your own space back.** `bgp` and EC2 mesh hosts reject their VPC's CIDRs, and `dx` rejects its announced prefixes. A default route is only accepted where the role's guide says so.
- **Narrow ownership.**
  - `bgp` and `dx` each own FRR's bgpd, so run one of them per FRR instance. `mesh` owns babeld's networks and its `RDM-*` filters.
  - Interfaces are only touched if they're named `rdm*` (`mesh`), `rdgre*` (`bgp`) or `rddx*` (`dx`).
  - AWS resources are only created with `bgp --register`, and only deleted if they carry the owner tag.

## Quick start

```bash
cargo build --release            # or --no-default-features for a mesh-only binary without the AWS SDK

# What would this host mesh? Needs neither FRR nor AWS.
route-discovery mesh inventory
route-discovery mesh render-frr

# Join the overlay: tunnels and babeld changes it would make (reads the registry, writes nothing)
route-discovery mesh plan --registry s3://my-mesh-bucket/prod
sudo route-discovery mesh run --apply --registry s3://my-mesh-bucket/prod

# On an EC2 instance: what does AWS say this instance peers with?
route-discovery bgp discover
route-discovery bgp run --register --sweep           # dry run: logs peers, tunnels and reloads it would make
sudo route-discovery bgp run --apply --register --sweep

# On a host that terminates Direct Connect VIFs itself
route-discovery dx discover --region eu-west-2
sudo route-discovery dx run --apply --region eu-west-2 --parent eth1=dxcon-abc123

route-discovery status --url http://127.0.0.1:9811/status   # bgp; dx is 9812, mesh is 9810
```

The only inputs are optional flags for things a host can't discover: the registry bucket (`--registry`), which physical port a Direct Connect connection uses (`--parent`), which ASN to register with (`--register-asn`), and interface include/exclude globs. Each role's guide lists them.

## Install as a service

**For the mesh overlay on many hosts, follow the [deployment runbook](docs/overlay-deployment.md)**: it creates the S3 registry and IAM roles (including IAM Roles Anywhere for bare metal), and installs the daemon with [`deploy/install-mesh.sh`](deploy/install-mesh.sh) by hand, through Systems Manager, or from a launch template. The steps below are the manual equivalent for any role.

1. Install FRR and enable the daemons the role needs:
   - `bgp` and `dx`: `bgpd` and `bfdd`, plus `frr-reload.py` (shipped with FRR as `/usr/lib/frr/frr-reload.py`).
   - `mesh`: `babeld`.
2. Create a `route-discovery` system user in the `frrvty` and `frr` groups, and install the binary at `/usr/local/bin/route-discovery`.
3. Grant AWS permissions:
   - `bgp`: [`bgp-aws-policy.json`](deploy/bgp-aws-policy.json), plus [`bgp-aws-register-policy.json`](deploy/bgp-aws-register-policy.json) for `--register` or `--sweep`.
   - `mesh` with `--registry`: [`mesh-aws-policy.json`](deploy/mesh-aws-policy.json).
   - `dx`: [`dx-aws-policy.json`](deploy/dx-aws-policy.json).
   - Hosts outside AWS use IAM Roles Anywhere or another credential process.
4. Install the matching unit from [`deploy/`](deploy): `route-discovery-bgp.service`, `route-discovery-dx.service` or `route-discovery-mesh.service`.

The units are `Type=notify` with a watchdog, and run with only `CAP_NET_ADMIN` where tunnels or VLANs are needed. Each role takes a lock on its state directory, so two controllers never manage the same plane.

## Development

```bash
make test     # unit and integration tests with fake IMDS, EC2, Direct Connect, S3 and FRR
make lint     # rustfmt and clippy, with and without the aws feature
make render   # mesh inventory and babeld fragment for this machine
```

Tests use fakes for IMDS, EC2, Direct Connect, S3, `ip` and FRR. Nothing has yet been validated against a live AWS account or FRR instance. Staging checks for each role are listed in its guide:
- AWS condition keys in the IAM policies;
- TGW Connect eBGP multihop;
- `frr-reload.py` behaviour on your FRR version;
- the running-config format that `mesh` parses;
- Babel over GRE, the `ipproto gre` rule and kernel-route redistribution on your kernel and FRR version (see [GRE overlay](docs/overlay.md)).

## Layout

| Path | Contents |
| --- | --- |
| `src/bgp/` | IMDS discovery, Route Server and TGW Connect peerings, GRE tunnels, self-registration and sweep, bgpd rendering |
| `src/dx/` | Direct Connect VIF discovery, VLAN links, bgpd rendering |
| `src/mesh/` | NIC inventory, babeld planning and verification |
| `src/mesh/overlay/` | S3 registry, relay selection, GRE tunnels, underlay pinning |
| `src/http.rs`, `src/supervision.rs`, `src/state.rs`, `src/commands.rs` | Status endpoint, systemd notify and signals, state lock, bounded subprocesses |
| `deploy/` | systemd units and IAM policies |
| `docs/` | Per-role guides |

MIT licensed.
