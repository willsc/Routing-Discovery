#!/usr/bin/env bash
# Prepare a host for the mesh role with a GRE overlay, and install route-discovery as a service.
# Safe to re-run: every step checks before it changes anything. Debian 12 and Ubuntu 22.04/24.04.
#
#   install-mesh.sh --registry s3://BUCKET/PREFIX --region REGION --binary SOURCE [options]
#   install-mesh.sh --peers-file FILE --binary SOURCE [options]
#
# Options:
#   --registry URL      S3 registry; hosts need AWS credentials for it
#   --region REGION     the registry bucket's region (with --registry)
#   --peers-file FILE   static JSON list of hosts instead of the registry; installed as
#                       /etc/route-discovery/peers.json, which the daemon re-reads every minute
#   --binary SOURCE     the route-discovery binary: a local path, an https:// URL or an s3:// URL
#                       (s3:// needs the AWS CLI). A matching SOURCE.sha256 is checked when present.
#   --platform metal    on bare metal; skips the 5 s IMDS probe at every start
#   --endpoint ADDR     bare metal: the tunnel endpoint, if not the source address of the default path
#   --aws-profile NAME  bare metal: credentials profile in --aws-config (IAM Roles Anywhere)
#   --aws-config FILE   bare metal: AWS config file holding that profile
#   --extra "ARGS"      further mesh flags, for example "--exclude mgmt0"
#   --start             enable and start the service now (default: install only)

set -euo pipefail

registry="" peers="" region="" binary="" platform="" endpoint="" profile="" config="" extra="" start=0
while (($#)); do
  case "$1" in
    --registry) registry="$2"; shift 2 ;;
    --region) region="$2"; shift 2 ;;
    --peers-file) peers="$2"; shift 2 ;;
    --binary) binary="$2"; shift 2 ;;
    --platform) platform="$2"; shift 2 ;;
    --endpoint) endpoint="$2"; shift 2 ;;
    --aws-profile) profile="$2"; shift 2 ;;
    --aws-config) config="$2"; shift 2 ;;
    --extra) extra="$2"; shift 2 ;;
    --start) start=1; shift ;;
    -h | --help) sed -n '2,/^$/p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
log() { echo "install-mesh: $*"; }
die() { echo "install-mesh: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run as root"
[[ -n $registry || -n $peers ]] || die "--registry s3://BUCKET/PREFIX or --peers-file FILE is required"
[[ -z $registry || -z $peers ]] || die "--registry and --peers-file are alternatives"
[[ -z $registry || $registry == s3://*/* ]] || die "--registry must be s3://BUCKET/PREFIX"
[[ -z $registry || -n $region ]] || die "--region is required with --registry"
[[ -z $peers || -r $peers ]] || die "cannot read $peers"
[[ -n $binary ]] || die "--binary is required"
[[ -z $profile || -n $config ]] || die "--aws-profile needs --aws-config"
[[ -z $config || -r $config ]] || die "cannot read $config"
command -v apt-get >/dev/null || die "only Debian and Ubuntu are supported"

log "kernel modules and sysctls"
printf 'ip_gre\ngre\n' >/etc/modules-load.d/route-discovery.conf
modprobe -a ip_gre gre
cat >/etc/sysctl.d/90-route-discovery.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
# Loose reverse-path filtering: overlay paths can be asymmetric.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv6.conf.all.disable_ipv6 = 0
EOF
sysctl --system >/dev/null

if ! dpkg -s frr >/dev/null 2>&1; then
  log "installing FRR 10"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -yq curl gnupg lsb-release
  curl -fsSL https://deb.frrouting.org/frr/keys.gpg -o /usr/share/keyrings/frrouting.gpg
  echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr $(lsb_release -sc) frr-10" \
    >/etc/apt/sources.list.d/frr.list
  apt-get update -q
  apt-get install -yq frr
  apt-mark hold frr >/dev/null
fi
if ! grep -q '^babeld=yes' /etc/frr/daemons; then
  log "enabling babeld"
  sed -i 's/^babeld=no/babeld=yes/' /etc/frr/daemons
  systemctl restart frr
fi
grep -q '^router babel' /etc/frr/frr.conf 2>/dev/null &&
  log "warning: /etc/frr/frr.conf has a router babel block; the mesh owns babeld, remove it"

id route-discovery >/dev/null 2>&1 ||
  useradd --system --no-create-home --shell /usr/sbin/nologin --groups frrvty route-discovery

log "fetching $binary"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fetch() {
  case "$1" in
    s3://*) aws s3 cp --only-show-errors ${region:+--region "$region"} "$1" "$2" ;;
    https://*) curl -fsSL -o "$2" "$1" ;;
    *) cp "$1" "$2" ;;
  esac
}
fetch "$binary" "$tmp/route-discovery"
if fetch "$binary.sha256" "$tmp/sha256" 2>/dev/null; then
  echo "$(cut -d' ' -f1 "$tmp/sha256")  $tmp/route-discovery" | sha256sum -c --quiet || die "checksum mismatch"
else
  log "no $binary.sha256; checksum not verified"
fi
"$tmp/route-discovery" --version >/dev/null || die "the binary does not run on this host"
install -m 0755 "$tmp/route-discovery" /usr/local/bin/route-discovery

unit=/etc/systemd/system/route-discovery-mesh.service
if [[ -r "$(dirname "$0")/route-discovery-mesh.service" ]]; then
  install -m 0644 "$(dirname "$0")/route-discovery-mesh.service" "$unit"
else
  fetch "${binary%/*}/route-discovery-mesh.service" "$tmp/unit" || die "no unit file next to this script or the binary"
  install -m 0644 "$tmp/unit" "$unit"
fi

if [[ -n $peers ]]; then
  install -d -m 0750 -g route-discovery /etc/route-discovery
  [[ $peers -ef /etc/route-discovery/peers.json ]] ||
    install -m 0640 -g route-discovery "$peers" /etc/route-discovery/peers.json
  args="--peers-file /etc/route-discovery/peers.json"
else
  args="--registry $registry --registry-region $region"
fi
[[ -n $platform ]] && args+=" --platform $platform"
[[ -n $endpoint ]] && args+=" --endpoint $endpoint"
[[ -n $extra ]] && args+=" $extra"
{
  echo "MESH_ARGS=\"$args\""
  if [[ -n $profile ]]; then
    install -d -m 0750 -g route-discovery /etc/route-discovery
    [[ $config -ef /etc/route-discovery/aws-config ]] ||
      install -m 0640 -g route-discovery "$config" /etc/route-discovery/aws-config
    echo "AWS_CONFIG_FILE=/etc/route-discovery/aws-config"
    echo "AWS_PROFILE=$profile"
  fi
} >"$tmp/env"
install -m 0640 -g route-discovery "$tmp/env" /etc/default/route-discovery-mesh
systemctl daemon-reload

if ((start)); then
  log "starting route-discovery-mesh"
  systemctl enable route-discovery-mesh
  systemctl restart route-discovery-mesh   # picks up a new binary on re-runs
else
  log "installed; preview with: sudo -u route-discovery bash -c 'set -a; . /etc/default/route-discovery-mesh; route-discovery mesh plan \$MESH_ARGS'"
  log "start with: systemctl enable --now route-discovery-mesh"
fi
