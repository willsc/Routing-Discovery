# Deploying and testing the GRE overlay

This runbook deploys the [GRE overlay](overlay.md) on EC2 instances and bare-metal hosts, proves each part works, then tests failover. Work through it in a pilot first: two peered VPCs and one bare-metal host. Then repeat sections 2 to 5 for production.

Nothing in the overlay has run against real AWS, kernels or FRR yet; only against test fakes. Section 6 checks the parts most likely to differ in a real environment.

## 0. Plan before you start

**Relays are chosen by seniority.** In each VPC, the first two hosts to start the service with `--apply` become its relays, and stay relays until they stop. Relays carry all of their VPC's traffic to other sites, so start the hosts you want as relays first, and size them for that traffic.

**Turning the overlay on changes traffic paths.** Traffic from a host in VPC A to a host in VPC B stops going directly over peering. It goes host → A relay → B relay → host, through tunnels. Measure throughput through the relays during the pilot (section 6.4).

Pilot layout:

| Where | Hosts | Role |
| --- | --- | --- |
| VPC A (peered with B) | `a1`, `a2` started first, then `a3` | `a1`, `a2` relays; `a3` ordinary |
| VPC B | `b1`, `b2` started first, then `b3` | `b1`, `b2` relays; `b3` ordinary |
| Outside AWS, reached over Direct Connect | `m1` | its own site and relay |

## 1. Build

On a build machine with the same CPU architecture as the hosts and an OS no newer than theirs (glibc compatibility), with Rust 1.89 or later:

```bash
git clone https://github.com/willsc/Routing-Discovery.git && cd Routing-Discovery
git checkout <commit>                # record it; production must run the same one
make test && make lint
cargo build --release --locked       # target/release/route-discovery
```

## 2. AWS setup (once)

### 2.1 Registry bucket

```bash
BUCKET=my-mesh-registry      # pick a name
PREFIX=pilot                 # one prefix per mesh; production gets its own
REGION=eu-west-2

aws s3api create-bucket --bucket $BUCKET --region $REGION \
  --create-bucket-configuration LocationConstraint=$REGION
aws s3api put-public-access-block --bucket $BUCKET --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
# Departed hosts expire; live hosts rewrite their entry every interval, so they never do.
aws s3api put-bucket-lifecycle-configuration --bucket $BUCKET --lifecycle-configuration '{
  "Rules": [{"ID": "expire-departed-hosts", "Status": "Enabled",
             "Filter": {"Prefix": "'$PREFIX'/hosts/"}, "Expiration": {"Days": 1}}]}'
```

Leave versioning off. If the bucket must be versioned, add a rule that expires noncurrent versions after 1 day.

### 2.2 IAM

Copy [`deploy/mesh-aws-policy.json`](../deploy/mesh-aws-policy.json), replacing `REGISTRY_BUCKET` and `REGISTRY_PREFIX`, and create it as a policy.

- **EC2:** attach it to the instance profile role of every mesh instance. The SDK picks up the role through IMDS.
- **Bare metal:** attach it to an IAM Roles Anywhere role, and set the host up with a certificate and `aws_signing_helper`. The credential setup is the same as for any on-prem workload: a `credential_process` profile in `/etc/route-discovery/aws-config`.

### 2.3 Network

Every host's endpoint must reach the endpoint of every host it tunnels to, without the overlay. These are the underlay paths:

- **VPC to VPC:** each VPC's route tables send the peer VPC's CIDR to the peering connection.
- **VPC to bare metal:** VPC route tables reach bare-metal endpoints through the VGW or TGW (route propagation from Direct Connect). Bare-metal hosts reach VPC CIDRs through the carrier.

Security groups on every mesh instance (cross-region peering can't reference security groups, so use CIDRs):

```bash
for CIDR in 10.1.0.0/16 10.2.0.0/16 192.168.50.5/32; do   # every VPC CIDR and bare-metal endpoint
  aws ec2 authorize-security-group-ingress --group-id $SG \
    --ip-permissions "IpProtocol=47,IpRanges=[{CidrIp=$CIDR}]" \
                     "IpProtocol=icmp,FromPort=3,ToPort=4,IpRanges=[{CidrIp=$CIDR}]"
done
```

The ICMP rule lets "fragmentation needed" messages through, which path MTU discovery needs. If you use network ACLs, allow protocol 47 both ways. Outside AWS, firewalls and carrier ACLs must pass GRE between bare-metal hosts and the VPC CIDRs.

Turn off source/destination check on every mesh instance, since any of them can become a relay:

```bash
aws ec2 modify-instance-attribute --instance-id i-... --no-source-dest-check
```

## 3. Host setup (every host)

Commands assume Ubuntu 24.04; Debian 12 is the same.

### 3.1 Kernel

```bash
printf 'ip_gre\ngre\n' | sudo tee /etc/modules-load.d/route-discovery.conf
sudo modprobe -a ip_gre gre

sudo tee /etc/sysctl.d/90-route-discovery.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
# Loose reverse-path filtering: overlay paths can be asymmetric.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv6.conf.all.disable_ipv6 = 0
EOF
sudo sysctl --system
```

The modules are loaded at boot because the service runs with `ProtectKernelModules=true`.

If a host firewall is active, allow GRE in, and Babel (UDP 6696) on tunnel interfaces, for example with nftables:

```
ip protocol gre accept
iifname "rdm*" udp dport 6696 accept
```

### 3.2 FRR

```bash
curl -s https://deb.frrouting.org/frr/keys.gpg | sudo tee /usr/share/keyrings/frrouting.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr $(lsb_release -sc) frr-10" \
  | sudo tee /etc/apt/sources.list.d/frr.list
sudo apt update && sudo apt install -y frr
sudo apt-mark hold frr                     # use the same version everywhere
sudo sed -i 's/^babeld=no/babeld=yes/' /etc/frr/daemons
sudo systemctl restart frr
```

Keep `router babel` out of `/etc/frr/frr.conf`: the mesh owns it.

### 3.3 route-discovery

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --groups frrvty route-discovery
sudo install -m 0755 route-discovery /usr/local/bin/route-discovery
sudo install -m 0644 deploy/route-discovery-mesh.service /etc/systemd/system/
sudo systemctl daemon-reload
```

`/etc/default/route-discovery-mesh` (mode 0640, owner `root:route-discovery`):

```bash
# EC2
MESH_ARGS="--registry s3://my-mesh-registry/pilot --registry-region eu-west-2"

# Bare metal: also the Roles Anywhere profile
# AWS_CONFIG_FILE=/etc/route-discovery/aws-config
# AWS_PROFILE=mesh
# MESH_ARGS="--registry s3://my-mesh-registry/pilot --registry-region eu-west-2 --platform metal"
```

On bare metal, add `--endpoint <address>` if the source address of the default path isn't the one the VPCs route back to. Add `--exclude` for NICs whose subnets must not be announced, such as a management network.

## 4. Preview (changes nothing)

On each host, as the service user:

```bash
mesh() { sudo -u route-discovery bash -c 'set -a; . /etc/default/route-discovery-mesh; exec /usr/local/bin/route-discovery mesh "$@" $MESH_ARGS' mesh "$@"; }
mesh inventory | jq .overlay     # identity, site, relays, peers as this host would see them
mesh plan                        # ip commands, then babeld changes
```

Check:
- `host`, `site` and `endpoint` are right: instance ID and VPC ID on EC2, `metal-…` on bare metal;
- no `errors` (for example, missing credentials or a wrong bucket region).

A preview reads the registry but never writes to it. Until some host runs with `--apply`, each host sees only itself.

## 5. Bring-up

Start the hosts in this order, checking each step before the next:

1. **First relays:** `a1`, then `b1`.
   ```bash
   sudo systemctl enable --now route-discovery-mesh
   journalctl -u route-discovery-mesh -f        # overlay_identity, overlay_role relay=true, overlay_command ...
   ```
   Within one registry interval (60 s), each should be a relay with a tunnel to the other.
2. **Second relays:** `a2`, `b2`.
3. **Bare metal:** `m1`.
4. **Ordinary hosts:** `a3`, `b3`, then the rest.

## 6. Verify

Run these on the host named. `T` is a tunnel name from the `tunnels` list in status.

### 6.1 Registry and roles

```bash
route-discovery status --url http://127.0.0.1:9810/status | jq .overlay
aws s3 ls s3://my-mesh-registry/pilot/hosts/
```

| Check | Expect |
| --- | --- |
| `relays` | `vpc-A: [a1, a2]`, `vpc-B: [b1, b2]`, `metal-…: [m1]`, the same on every host |
| `relay` on `a1` | `true`; its peers are `a2`, `a3`, `b1`, `b2`, `m1` |
| `relay` on `a3` | `false`; its peers are `a1`, `a2` only |
| `stale`, `errors` | empty |

### 6.2 Tunnels and Babel

```bash
ip -d link show type gre                    # rdm…: gre, local/remote endpoints, mtu 1476, MULTICAST, UP
ip -4 addr show dev T                       # inet 169.254.x.y peer 169.254.p.q/32
sudo vtysh -c 'show babel neighbor'         # one neighbour per tunnel, with reasonable rxcost
sudo vtysh -c 'show ip route babel'         # remote VPC CIDRs and bare-metal subnets via 169.254.p.q, rdm…
sudo vtysh -c 'show running-config babeld'  # networks are only rdm… on EC2
```

On a relay, also check the VPC's CIDRs are originated and redistributed:

```bash
ip route show proto 249                     # 10.1.0.0/16 via <VPC router> on a1
sudo vtysh -c 'show running-config babeld' | grep redistribute    # includes "redistribute ipv4 kernel"
```

On `b1`, `show ip route babel` must include `10.1.0.0/16` from `a1` or `a2`. These are the checks most likely to fail:
- if FRR's babeld doesn't redistribute kernel routes on your version, relays advertise nothing for their VPC;
- if `show babel neighbor` lists neighbours but `show ip route babel` is empty, IPv4 next hops aren't working over the tunnels. Check the 169.254 pair on both ends.

### 6.3 Tunnel packets stay on the underlay

```bash
ip rule show | grep 4242                    # 4242: from all ipproto gre lookup 4242
ip route show table 4242                    # one /32 per tunnel endpoint, via the VPC router or the carrier
ip route get <b1 endpoint> ipproto gre      # table 4242 via ens5, never dev rdm…
ip route get <host in VPC B>                # dev rdm…: normal traffic does use the overlay
```

Send GRE packets across while watching the underlay NIC; you should see GRE, never GRE inside GRE:

```bash
sudo tcpdump -ni ens5 'proto gre' -c 20 -v
```

### 6.4 Traffic paths

| From → to | Command | Expect |
| --- | --- | --- |
| `a3` → `a1`'s VPC subnet neighbour | `ip route get <host in VPC A>` on `a3` | `dev ens5`: within a VPC, no tunnel |
| `a3` → `b3` | `traceroute -n <b3>` | `a1` or `a2`, then `b1` or `b2`, then `b3` |
| `m1` → `b3` | `traceroute -n <b3>` | `b1` or `b2`, then `b3` |
| MTU | `ping -M do -s 1448 <b3>` from `a3` | replies; `-s 1449` reports "message too long" |
| Throughput | `iperf3` between `a3` and `b3`, then several pairs at once | note relay CPU and bandwidth |

## 7. Failover tests

Keep a continuous ping running for each test and count lost packets: `ping -i 0.2 <target> | ts` (from `moreutils`).

1. **Direct Connect path lost (the leased-line case).** On the VIF that carries `m1`'s traffic to VPC A:
   ```bash
   aws directconnect start-bgp-failover-test --virtual-interface-id dxvif-... --test-duration-in-minutes 5
   ```
   Watch `m1` → host in VPC A. The tunnels from `m1` to `a1`/`a2` go quiet, and `traceroute` should switch to `b1`/`b2` → `a1`/`a2`. Loss should be a few seconds. When the test ends, the direct path should come back.

   Without Direct Connect access, simulate it on `m1`: `sudo nft add table inet t; sudo nft add chain inet t o '{type filter hook output priority 0;}'; sudo nft add rule inet t o ip daddr { <a1>, <a2> } ip protocol gre drop`. Remove it with `sudo nft delete table inet t`.
2. **Relay lost:** stop `a1` (`sudo systemctl stop frr`, or stop the instance). Traffic from `a3` should continue via `a2` with a few seconds of loss. After about 5 minutes (5 × `--registry-interval`), `a3` is elected as the new relay. When `a1` returns, it takes the role back from `a3`, because its registry entry is older. Expect a few seconds of rerouting each time the role moves.
3. **Registry lost:** remove the bucket permission from one host's role. Status shows a `registry:` error; tunnels and routes stay up. Restore the permission.
4. **Controller restart:** `sudo systemctl restart route-discovery-mesh`. No packet loss.
5. **FRR restart:** `sudo systemctl restart frr`. Babel config is reapplied within one pass (2 s); expect loss only while adjacencies re-form.
6. **Reboot** a relay and an ordinary host. Both come back with the same relay or ordinary role, and with no manual steps.
7. **Withdraw** on one ordinary host:
   ```bash
   sudo systemctl stop route-discovery-mesh
   sudo route-discovery mesh withdraw --apply
   ip -d link show type gre; ip rule show | grep 4242; ip route show table 4242   # all empty
   ```
   The host is back to plain VPC routing. Start the service again to rejoin.

## 8. Rollback

Per host: stop the service and run `mesh withdraw --apply`, as in test 7. To roll back a whole site, do its ordinary hosts first, then its relays. Traffic returns to direct peering and Direct Connect routing.

## 9. Production

Repeat sections 2 to 5 with a new registry prefix (for example `prod`), using the same binary commit and FRR version as the pilot.
- Start each VPC's intended relays first.
- Add ordinary hosts in batches.
- Run test 7.1 on each Direct Connect path before relying on it.
