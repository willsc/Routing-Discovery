# GRE overlay

`route-discovery mesh run --apply --registry s3://bucket/prefix` joins a host to a routed overlay that spans VPCs, VPC peering, Direct Connect and leased lines. Every host runs it, on EC2 and on bare metal outside AWS. There is no edge router: hosts build GRE tunnels to each other and run Babel over them, so when a leased line or Direct Connect path fails, routing on the hosts reconfigures itself within seconds.

Babel normally finds neighbours with link-local multicast, which VPCs, peering and the AWS backbone don't carry. Tunnels give every adjacency a point-to-point link that does.

![How the overlay hangs together: who tunnels to whom, the registry and reconcile loops, how a packet leaves through a tunnel, and failover when a Direct Connect path fails](images/overlay.svg)

## How hosts find each other

Each host writes one JSON object to `s3://bucket/prefix/hosts/<host>.json`: its host ID, hostname, site, platform, tunnel endpoint and the time it first registered. It rewrites it every `--registry-interval` (default 60 s) and lists the prefix to see everyone else.

- **Heartbeat:** S3's LastModified time. Ages are measured against this host's own last write, so a skewed local clock doesn't matter. A host silent for 5 intervals is ignored.
- **Cheap reads:** an unchanged entry keeps its ETag, so after the first sync a host only downloads entries that changed.
- **Identity:**
  - EC2: the instance ID; the site is the VPC ID; the endpoint is the primary private IPv4 address (all from IMDS).
  - Bare metal: `metal-` plus the first 16 characters of `/etc/machine-id`; the site is the host itself; the endpoint is the source address of the default path.
  - `--site` and `--endpoint` override these. `--platform ec2|metal` skips the IMDS probe.

## Who tunnels to whom

Every host computes the same answer from the same registry view, so nothing coordinates centrally.

- **Relays:** each site's `--relays` (default 2) most senior live hosts: earliest first registration, then host ID. A new host never displaces a relay; a relay is replaced only when it stops sending heartbeats.
- **Relay:** tunnels to every relay of every other site, and to every other host in its own site.
- **Any other host:** tunnels to its own site's relays only.
- **Bare-metal host:** a site of one, so it is always a relay and tunnels to every relay of every VPC.

With 500 hosts in 20 VPCs, an ordinary host has 2 tunnels and a relay about 60.

Each tunnel is a GRE interface `rdm<hash of the peer's host ID>` with MTU `--tunnel-mtu`, the MULTICAST flag, an IPv6 link-local address for Babel's hellos, and a point-to-point IPv4 pair in 169.254/16 (for example `169.254.12.7 peer 169.254.201.33`). FRR's babeld announces IPv4 routes with an IPv4 next hop, which is what the pair provides. Each host's addresses are derived from its host ID, and avoid 169.254.169.x and 169.254.170.x, where AWS runs IMDS, DNS and the ECS endpoints. They are link-local, so they are never published.

## What gets routed

| Host | Babel runs on | Advertises | Never learns |
| --- | --- | --- | --- |
| EC2 relay | its tunnels only | its VPC's CIDRs, plus routes from other sites (transit) | its own VPC's CIDRs |
| Other EC2 host | its tunnels only | nothing (a leaf) | its own VPC's CIDRs |
| Bare metal | its tunnels and its NICs | its connected subnets, plus transit | nothing extra |

Traffic within a VPC always stays on the VPC fabric. Traffic between sites leaves the source host through a tunnel and arrives on the destination relay, which delivers it on its VPC.

A relay originates its VPC's CIDRs as kernel routes via the VPC router (route protocol 249), which babeld redistributes. The VPC subnet on the relay's own NIC is withheld, because the CIDR covers it.

## Failover

When a leased line or Direct Connect path fails, the tunnels whose packets used it stop passing hellos. Babel drops those neighbours after a few missed hellos (seconds at the default 1 s interval) and switches to the best path that remains. For example, bare metal → VPC B's relay → VPC A's relay over peering. Because the traffic is GRE between hosts, peering only ever carries host-to-host packets, so the restriction that peering won't pass traffic through a VPC doesn't apply.


If a relay fails, the site's hosts still have tunnels to the other relay, so nothing waits for a new relay to be chosen. A replacement is picked once the dead relay misses 5 heartbeats (5 minutes by default).

If S3 is unreachable, the overlay keeps its current tunnels and routes, and reports the error in status. The registry only matters when hosts join, leave or change.

## Two loops

The registry sync decides who this host tunnels to. The reconcile pass makes the kernel and FRR match, and repairs drift such as an FRR restart within one pass. Failover waits for neither: Babel does it between passes.

## Keeping tunnel packets on the underlay

Babel learns routes that cover tunnel endpoints: a remote VPC's CIDR covers its relays. If GRE packets followed those routes, a tunnel would end up inside itself. So:

- an `ip rule` at priority 4242 sends locally generated GRE packets (IP protocol 47) to routing table 4242;
- table 4242 holds one `/32` per tunnel endpoint, copied from the best main-table route that is neither a Babel route nor via a tunnel;
- if there is no such route, the entry is `unreachable`. The tunnel stays quiet and Babel routes around it, instead of tunnelling through itself.


Endpoint routes are refreshed every pass (2 s), so they follow underlay changes, for example when the carrier moves a VPC's route to another Direct Connect connection.

## Prerequisites

On every host:

- FRR with `babeld=yes`, and `zebra` running.
- Kernel modules `ip_gre` and `gre` loaded at boot (`/etc/modules-load.d/`); the service runs with `ProtectKernelModules=true`.
- IP forwarding on (`net.ipv4.ip_forward=1`, `net.ipv6.conf.all.forwarding=1`), since any host can become a relay.
- Loose reverse-path filtering (`net.ipv4.conf.all.rp_filter=2`). Paths through the overlay can be asymmetric.
- IPv6 not disabled: Babel speaks IPv6 link-local inside each tunnel.
- The [mesh unit](../deploy/route-discovery-mesh.service), with `MESH_ARGS="--registry s3://…"` in `/etc/default/route-discovery-mesh`.

In AWS:

- **Security groups and network ACLs:** allow IP protocol 47 (GRE) between every mesh host's endpoint, and ICMP "fragmentation needed". Allow GRE only from mesh endpoints (see Security).
- **Source/destination check:** turn it off on every mesh instance (`aws ec2 modify-instance-attribute --no-source-dest-check`, from your provisioning tooling). Relays deliver decapsulated traffic onto their VPC with the original source address.
- **IAM:** grant [`deploy/mesh-aws-policy.json`](../deploy/mesh-aws-policy.json), with the bucket and prefix filled in. Bare-metal hosts use IAM Roles Anywhere or another credential process, as for the dx role.
- **S3 bucket:** versioning off (or expire noncurrent versions quickly), plus a lifecycle rule that expires `prefix/hosts/` objects after 1 day. Live hosts rewrite their entry every interval, so only departed hosts expire.

Outside AWS: firewalls and carrier ACLs must pass GRE between the bare-metal hosts and the VPC endpoints.

## Cost and scale

Each host makes one PUT and one LIST per interval, plus a GET per changed entry. At 500 hosts and the default 60 s interval, that is about 21.6 million PUTs and 21.6 million LISTs a month: roughly $220 a month at standard S3 request prices. Raising `--registry-interval` cuts this proportionally. It only slows down noticing joins and departures; failover itself is Babel's job and doesn't depend on it.

## MTU

Tunnels default to MTU 1476: a 1500-byte underlay, such as inter-region peering or a 1500-byte Direct Connect VIF, minus the 24-byte GRE header. Raise `--tunnel-mtu` only if every path between every pair of sites carries jumbo frames.

## Security

GRE has no encryption or authentication, and FRR's babeld doesn't implement Babel authentication. Anyone who can deliver GRE to a host's endpoint, with a source address it accepts, can inject routes within the `--accept` supernets. Direct Connect and leased lines carry the traffic in cleartext. Mitigations:

- allow protocol 47 only from mesh endpoints, in security groups, network ACLs and carrier ACLs;
- keep `--accept` as narrow as your address plan allows;
- write access to the registry prefix lets a principal add a peer, so grant `s3:PutObject` on it only to mesh hosts.

If any underlay is untrusted, encrypted tunnels (WireGuard or IPsec) are the safer choice.

## Ownership

On top of what the [mesh](mesh.md) owns, the overlay owns interfaces named `rdm*`, routing table 4242, the `ip rule` at priority 4242, and main-table routes with protocol 249. `mesh withdraw --apply` removes all of them after removing babeld's configuration.

## Status

`route-discovery status --url http://127.0.0.1:9810/status` includes an `overlay` object: this host's registry entry, whether it is a relay, every site's relays, its peers and tunnels, endpoint pins, ignored hosts with the reason (`stale`), and registry errors. `/metrics` adds `mesh_tunnels`.

`route-discovery mesh plan --registry …` prints the overlay's `ip` commands, followed by the babeld changes, without writing anything to S3 or the host.

## Not implemented

- IPv6 tunnel endpoints.
- Encrypted tunnels.
- Letting non-mesh resources in a VPC (for example RDS) reach other sites first. They can be reached from other sites, because relays advertise the whole VPC, but their VPC route tables don't point anywhere in the overlay. The `bgp` role with VPC Route Server could add those routes.
- Several sites sharing one bare-metal LAN without `--site`.
