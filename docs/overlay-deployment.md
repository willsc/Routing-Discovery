# Deploying and testing the GRE overlay

This runbook deploys the [GRE overlay](overlay.md) on EC2 instances and bare-metal hosts, proves each part works, then tests failover. Work through it in a pilot first: two peered VPCs and one bare-metal host. Then repeat sections 2 to 5 for production.

Nothing in the overlay has run against real AWS, kernels or FRR yet; only against test fakes. Section 6 checks the parts most likely to differ in a real environment.

## 0. Plan before you start

**Registry or peers file.** This runbook uses the S3 registry. If you would rather hosts hold no AWS credentials, use a peers file instead; section 3.5 lists what changes.

**Relays are chosen by seniority.** In each VPC, the first two hosts to start the service with `--apply` become its relays, and stay relays until they stop. Relays carry all of their VPC's traffic to other sites, so start the hosts you want as relays first, and size them for that traffic.

**Turning the overlay on changes traffic paths.** Traffic from a host in VPC A to a host in VPC B stops going directly over peering. It goes host → A relay → B relay → host, through tunnels. Measure throughput through the relays during the pilot (section 6.4).

Pilot layout:

| Where | Hosts | Role |
| --- | --- | --- |
| VPC A (peered with B) | `a1`, `a2` started first, then `a3` | `a1`, `a2` relays; `a3` ordinary |
| VPC B | `b1`, `b2` started first, then `b3` | `b1`, `b2` relays; `b3` ordinary |
| Outside AWS, reached over Direct Connect | `m1` | its own site and relay |

## 1. Build and publish a release

On a build machine with the same CPU architecture as the hosts and an OS no newer than theirs (glibc compatibility), with Rust 1.89 or later:

```bash
git clone https://github.com/willsc/Routing-Discovery.git && cd Routing-Discovery
git checkout <commit>                # record it; production must run the same one
make test && make lint
cargo build --release --locked       # target/release/route-discovery
```

Once the registry bucket exists (2.1, with `$BUCKET` set), publish the build to it under `releases/<commit>/`. Every host installs from there, so all of them run exactly the same build:

```bash
COMMIT=$(git rev-parse --short HEAD)
DEST=s3://$BUCKET/releases/$COMMIT
cp target/release/route-discovery /tmp/route-discovery
(cd /tmp && sha256sum route-discovery > route-discovery.sha256)
aws s3 cp /tmp/route-discovery $DEST/route-discovery
aws s3 cp /tmp/route-discovery.sha256 $DEST/route-discovery.sha256
aws s3 cp deploy/route-discovery-mesh.service $DEST/route-discovery-mesh.service
aws s3 cp deploy/install-mesh.sh $DEST/install-mesh.sh
```

## 2. AWS setup (once)

Set these for the rest of this section:

```bash
BUCKET=my-mesh-registry      # pick a name
PREFIX=pilot                 # one prefix per mesh; production gets its own
REGION=eu-west-2
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
```

### 2.1 Registry bucket

The registry is nothing more than this bucket: each host writes `$PREFIX/hosts/<host>.json` and reads the others. There is no server to run.

```bash
aws s3api create-bucket --bucket $BUCKET --region $REGION \
  --create-bucket-configuration LocationConstraint=$REGION
aws s3api put-public-access-block --bucket $BUCKET --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
# Departed hosts expire; live hosts rewrite their entry every interval, so they never do.
aws s3api put-bucket-lifecycle-configuration --bucket $BUCKET --lifecycle-configuration '{
  "Rules": [{"ID": "expire-departed-hosts", "Status": "Enabled",
             "Filter": {"Prefix": "'$PREFIX'/hosts/"}, "Expiration": {"Days": 1}}]}'
```

Leave versioning off. If the bucket must be versioned, add a rule that expires noncurrent versions after 1 day. Hosts outside AWS reach S3 over the internet or an S3 interface endpoint; they only need HTTPS to it.

Check it from your workstation: `aws s3 ls s3://$BUCKET/$PREFIX/hosts/` is empty until the first host starts with `--apply`.

### 2.2 IAM policies

```bash
sed "s/REGISTRY_BUCKET/$BUCKET/; s#REGISTRY_PREFIX#$PREFIX#g" deploy/mesh-aws-policy.json > /tmp/mesh-policy.json
sed "s/REGISTRY_BUCKET/$BUCKET/" deploy/mesh-release-policy.json > /tmp/mesh-release-policy.json
aws iam create-policy --policy-name route-discovery-mesh --policy-document file:///tmp/mesh-policy.json
aws iam create-policy --policy-name route-discovery-mesh-release --policy-document file:///tmp/mesh-release-policy.json
MESH_POLICY=arn:aws:iam::$ACCOUNT:policy/route-discovery-mesh
RELEASE_POLICY=arn:aws:iam::$ACCOUNT:policy/route-discovery-mesh-release
```

`route-discovery-mesh` is what the daemon needs at run time: list, read and write the registry prefix, nothing else. `route-discovery-mesh-release` lets the installer download releases.

### 2.3 IAM for EC2 instances

If your instances already have an instance profile, attach both policies to its role instead, and skip to the last command.

```bash
aws iam create-role --role-name route-discovery-mesh --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name route-discovery-mesh --policy-arn $MESH_POLICY
aws iam attach-role-policy --role-name route-discovery-mesh --policy-arn $RELEASE_POLICY
# For installing through Systems Manager (section 3.2):
aws iam attach-role-policy --role-name route-discovery-mesh \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
aws iam create-instance-profile --instance-profile-name route-discovery-mesh
aws iam add-role-to-instance-profile --instance-profile-name route-discovery-mesh --role-name route-discovery-mesh

# Each existing instance:
aws ec2 associate-iam-instance-profile --instance-id i-... --iam-instance-profile Name=route-discovery-mesh
```

The daemon finds these credentials through IMDS; there is nothing to configure on the host.

### 2.4 IAM for bare-metal hosts (IAM Roles Anywhere)

Bare-metal hosts get temporary credentials for the same policies by presenting an X.509 certificate from a CA you control. You need one CA certificate (`ca.pem`), and per host a certificate and key it signed (`m1.pem`, `m1.key`). The certificates need `digitalSignature` key usage and must not be CA certificates.

```bash
ANCHOR=$(aws rolesanywhere create-trust-anchor --name route-discovery-mesh --enabled \
  --source "sourceType=CERTIFICATE_BUNDLE,sourceData={x509CertificateData=$(cat ca.pem)}" \
  --query trustAnchor.trustAnchorArn --output text)
sed "s#TRUST_ANCHOR_ARN#$ANCHOR#" deploy/mesh-rolesanywhere-trust.json > /tmp/trust.json
aws iam create-role --role-name route-discovery-mesh-metal --assume-role-policy-document file:///tmp/trust.json
aws iam attach-role-policy --role-name route-discovery-mesh-metal --policy-arn $MESH_POLICY
aws iam attach-role-policy --role-name route-discovery-mesh-metal --policy-arn $RELEASE_POLICY
ROLE=arn:aws:iam::$ACCOUNT:role/route-discovery-mesh-metal
PROFILE=$(aws rolesanywhere create-profile --name route-discovery-mesh --enabled --role-arns $ROLE \
  --query profile.profileArn --output text)
echo "$ANCHOR $PROFILE $ROLE"     # needed on every bare-metal host
```

Section 3.1 sets up each bare-metal host to use these.

### 2.5 Network

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

Turn off source/destination check on every mesh instance, since any of them can become a relay. For every instance tagged `route-discovery=mesh`:

```bash
for ID in $(aws ec2 describe-instances --filters Name=tag:route-discovery,Values=mesh Name=instance-state-name,Values=running \
              --query 'Reservations[].Instances[].InstanceId' --output text); do
  aws ec2 modify-instance-attribute --instance-id $ID --no-source-dest-check
done
```

For new instances, run the loop again after launch, or have your provisioning tool do it (Terraform `source_dest_check = false`, CloudFormation `SourceDestCheck: false`).

## 3. Install the daemon on every host

[`deploy/install-mesh.sh`](../deploy/install-mesh.sh) does the whole host setup, on Debian 12 and Ubuntu 22.04/24.04. It is safe to re-run, which is also how you upgrade:

1. loads `ip_gre` and `gre` at boot, and sets forwarding and loose reverse-path filtering;
2. installs FRR 10 from the FRR apt repository, holds its version, and enables babeld;
3. creates the `route-discovery` user, in the `frrvty` group;
4. downloads the binary, checks its SHA-256, and installs it at `/usr/local/bin/route-discovery`;
5. installs the systemd unit and writes `/etc/default/route-discovery-mesh` with the flags;
6. with `--start`, enables and (re)starts the service. Without it, it stops there, so you can preview first.

It needs the AWS CLI on the host to download from `s3://`; Amazon Linux has it, on Ubuntu use `snap install aws-cli --classic`. Alternatively, pass a local path or an `https://` URL as `--binary`.

If a host firewall is active, also allow GRE in, and Babel (UDP 6696) on tunnel interfaces, for example with nftables:

```
ip protocol gre accept
iifname "rdm*" udp dport 6696 accept
```

Keep `router babel` out of `/etc/frr/frr.conf`: the mesh owns it. The installer warns if it finds one.

### 3.1 One host by hand

```bash
REL=s3://$BUCKET/releases/$COMMIT
aws s3 cp $REL/install-mesh.sh . && chmod +x install-mesh.sh

# EC2
sudo ./install-mesh.sh --registry s3://$BUCKET/$PREFIX --region $REGION --binary $REL/route-discovery
```

On bare metal, first install [`aws_signing_helper`](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html) at `/usr/local/bin/aws_signing_helper`, and copy `install-mesh.sh`, `route-discovery-mesh.service` and the binary to the host from the release (the host has no AWS credentials yet). Then, with `$ANCHOR`, `$PROFILE` and `$ROLE` from 2.4:

```bash
# The profile the daemon will use. It holds no secrets.
cat > aws-config <<EOF
[profile mesh]
region = $REGION
credential_process = /usr/local/bin/aws_signing_helper credential-process --certificate /etc/route-discovery/mesh.pem --private-key /etc/route-discovery/mesh.key --trust-anchor-arn $ANCHOR --profile-arn $PROFILE --role-arn $ROLE
EOF

# Creates the route-discovery user and copies aws-config to /etc/route-discovery/.
sudo ./install-mesh.sh --registry s3://$BUCKET/$PREFIX --region $REGION --binary ./route-discovery \
  --platform metal --aws-profile mesh --aws-config ./aws-config

# This host's certificate and key, readable by the service only
sudo install -m 0640 -g route-discovery m1.pem /etc/route-discovery/mesh.pem
sudo install -m 0640 -g route-discovery m1.key /etc/route-discovery/mesh.key

# Check: should print the route-discovery-mesh-metal role
sudo -u route-discovery env AWS_CONFIG_FILE=/etc/route-discovery/aws-config AWS_PROFILE=mesh aws sts get-caller-identity
```

Once the host has credentials, upgrades can use `--binary s3://…` like EC2.

On bare metal, add `--endpoint <address>` if the source address of the default path isn't the one the VPCs route back to, and `--extra "--exclude mgmt0"` for NICs whose subnets must not be announced, such as a management network.

### 3.2 Existing EC2 instances, through Systems Manager

For every running instance tagged `route-discovery=mesh` (the SSM agent must be running, as it is on Amazon Linux and Ubuntu AMIs):

```bash
aws ssm send-command --document-name AWS-RunShellScript \
  --targets Key=tag:route-discovery,Values=mesh \
  --max-concurrency 10% --max-errors 1 \
  --parameters commands="[
    \"command -v aws || snap install aws-cli --classic\",
    \"aws s3 cp s3://$BUCKET/releases/$COMMIT/install-mesh.sh /root/install-mesh.sh\",
    \"bash /root/install-mesh.sh --registry s3://$BUCKET/$PREFIX --region $REGION --binary s3://$BUCKET/releases/$COMMIT/route-discovery\"
  ]"
aws ssm list-command-invocations --command-id <id> --details --query 'CommandInvocations[].[InstanceId,Status]'
```

This installs without starting, so the bring-up order in section 5 still applies. To start a batch afterwards, run the same command with `systemctl enable --now route-discovery-mesh`. Upgrading later is the same command with a new `$COMMIT` and `--start`; `--max-concurrency` keeps most hosts routing while it rolls.

### 3.3 New EC2 instances, through a launch template

Add this as user data to the launch template or Auto Scaling group, with the `route-discovery-mesh` instance profile. New instances join as ordinary hosts once the relays exist, so they can start straight away:

```bash
#!/bin/bash
set -euo pipefail
command -v aws || snap install aws-cli --classic
REL=s3://my-mesh-registry/releases/<commit>
aws s3 cp $REL/install-mesh.sh /root/install-mesh.sh
bash /root/install-mesh.sh --registry s3://my-mesh-registry/pilot --region eu-west-2 --binary $REL/route-discovery --start
```

Source/destination check still has to be turned off on each new instance (see 2.5).

### 3.4 Bare-metal fleets

Use whatever already manages those hosts (Ansible, Salt, Puppet) to repeat the bare-metal steps from 3.1: the signing helper, `aws-config`, `install-mesh.sh` with the bare-metal flags, then the host's own certificate and key. `aws-config` is the same on every host; each host needs its own certificate.

### 3.5 With a peers file instead of the registry

Skip 1's S3 upload, and 2.1 to 2.4: no bucket, IAM role or Roles Anywhere. Section 2.5 (network) still applies.

1. Write the list, starting from [`deploy/peers.example.json`](../deploy/peers.example.json). Put each VPC's intended relays first; file order picks them. Keep it in your configuration repository.
2. Install on each host with the file and a local or `https://` binary:
   ```bash
   sudo ./install-mesh.sh --peers-file peers.json --binary ./route-discovery [--platform metal]
   ```
   It is installed as `/etc/route-discovery/peers.json`.
3. To add or remove a host later, update the file on every host (for example with Ansible). Hosts pick up the change within `--registry-interval`; nothing restarts.

Bring-up order (section 5) no longer matters: relays come from the file, not from start order. In section 6.1, `aws s3 ls` doesn't apply; `route-discovery status` shows the relays the file selects.

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
