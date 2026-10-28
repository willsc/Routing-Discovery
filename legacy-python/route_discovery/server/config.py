from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
import tomllib

from ..config import ConfigError, address, check_keys, name, number


def resource(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r"-[0-9a-f]{8,17}", value):
        raise ConfigError(f"expected a {prefix} resource ID")
    return value


def networks(values, required=True):
    if not isinstance(values, list) or (required and not values) or len(values) > 256:
        raise ConfigError("prefix allowlists must be arrays of 1–256 canonical networks")
    try:
        result = tuple(str(ipaddress.ip_network(v, strict=True)) for v in values)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    if len(set(result)) != len(result):
        raise ConfigError("duplicate prefix in allowlist")
    return result


def permits(prefix, allowed):
    net = ipaddress.ip_network(prefix)
    return any(net.version == (parent := ipaddress.ip_network(p)).version and net.subnet_of(parent) for p in allowed)


@dataclass(frozen=True)
class Endpoint:
    id: str
    address: str
    router_id: str
    socket_dir: str


@dataclass(frozen=True)
class Peer:
    id: str
    endpoint: str
    address: str
    asn: int
    eni: str
    next_hops: tuple[str, ...]
    allowed_prefixes: tuple[str, ...]
    max_prefixes: int = 100
    local_pref: int = 100
    bfd: bool = True


@dataclass(frozen=True)
class Propagation:
    table: str
    allowed_prefixes: tuple[str, ...] = ()
    enabled: bool = True
    max_routes: int = 100


@dataclass(frozen=True)
class ServerConfig:
    id: str
    asn: int
    region: str
    vpc_id: str
    endpoints: tuple[Endpoint, ...]
    peers: tuple[Peer, ...]
    propagations: tuple[Propagation, ...]
    state_dir: str = "/var/lib/route-discovery-server"
    listen: str = "127.0.0.1"
    port: int = 9809
    poll_interval: float = 1.0
    reconcile_interval: float = 5.0
    stale_after: float = 10.0
    failback_delay: float = 10.0
    persist_routes: bool = False
    persist_duration: float = 60.0
    owner_tag: str = "route-discovery-server"


def load(path):
    try:
        with Path(path).open("rb") as stream:
            return parse(tomllib.load(stream))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ConfigError(str(exc)) from exc


def parse(raw):
    check_keys(raw, {"server", "endpoints", "peers", "propagations"}, "route-server config")
    s = raw.get("server", {})
    check_keys(s, set(ServerConfig.__dataclass_fields__) - {"endpoints", "peers", "propagations"}, "server")
    sid = name(s.get("id"), "server.id")
    asn = number(s.get("asn"), "server.asn", 1, 2**32 - 1, True)
    region = s.get("region")
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", region):
        raise ConfigError("server.region is required")
    vpc = resource(s.get("vpc_id"), "vpc")
    endpoints, peers, propagations = [], [], []
    for key, upper in (("endpoints", 16), ("peers", 128), ("propagations", 64)):
        if not isinstance(raw.get(key), list) or not 1 <= len(raw[key]) <= upper:
            raise ConfigError(f"configure 1–{upper} {key}")
    for e in raw["endpoints"]:
        check_keys(e, set(Endpoint.__dataclass_fields__), "endpoint")
        eid = name(e.get("id"), "endpoint.id")
        addr = address(e.get("address"), "endpoint.address")
        router_id = str(ipaddress.IPv4Address(e.get("router_id")))
        sock = e.get("socket_dir")
        if not isinstance(sock, str) or not Path(sock).is_absolute() or "\n" in sock:
            raise ConfigError("endpoint.socket_dir must be an absolute FRR socket directory")
        endpoints.append(Endpoint(eid, addr, router_id, sock))
    for attribute in ("id", "address", "router_id", "socket_dir"):
        if len({getattr(e, attribute) for e in endpoints}) != len(endpoints):
            raise ConfigError(f"endpoints require unique {attribute} values")
    ep_map = {e.id: e for e in endpoints}
    for p in raw["peers"]:
        check_keys(p, set(Peer.__dataclass_fields__), "peer")
        pid = name(p.get("id"), "peer.id")
        if p.get("endpoint") not in ep_map:
            raise ConfigError(f"{pid}: unknown endpoint")
        addr = address(p.get("address"), "peer.address")
        ep = ep_map[p["endpoint"]]
        if ipaddress.ip_address(addr).version != ipaddress.ip_address(ep.address).version or addr == ep.address:
            raise ConfigError("peer and endpoint need different addresses in the same address family")
        peer_asn = number(p.get("asn"), "peer.asn", 1, 2**32 - 1, True)
        if asn == peer_asn:
            raise ConfigError("route-server peers must use eBGP with a different ASN")
        hops = p.get("next_hops")
        if not isinstance(hops, list) or not 1 <= len(hops) <= 8:
            raise ConfigError("each peer needs 1–8 next_hops mapped to its ENI")
        hops = tuple(address(h, "next_hop") for h in hops)
        if len(set(hops)) != len(hops):
            raise ConfigError("duplicate next hop")
        if not isinstance(p.get("bfd", True), bool):
            raise ConfigError("bfd must be boolean")
        peers.append(Peer(pid, p["endpoint"], addr, peer_asn, resource(p.get("eni"), "eni"), hops,
                          networks(p.get("allowed_prefixes")),
                          number(p.get("max_prefixes", 100), "max_prefixes", 1, 10000, True),
                          number(p.get("local_pref", 100), "local_pref", 0, 2**32 - 1, True),
                          p.get("bfd", True)))
    if len({p.id for p in peers}) != len(peers) or len({(p.endpoint, p.address) for p in peers}) != len(peers):
        raise ConfigError("duplicate peer ID or endpoint/peer address")
    for e in endpoints:
        if not any(p.endpoint == e.id for p in peers):
            raise ConfigError(f"endpoint {e.id} has no peers")
    for t in raw["propagations"]:
        check_keys(t, set(Propagation.__dataclass_fields__), "propagation")
        if not isinstance(t.get("enabled", True), bool):
            raise ConfigError("propagation.enabled must be boolean")
        propagations.append(Propagation(resource(t.get("table"), "rtb"), networks(t.get("allowed_prefixes", []), False),
                                        t.get("enabled", True), number(t.get("max_routes", 100), "max_routes", 1, 10000, True)))
    if len({t.table for t in propagations}) != len(propagations):
        raise ConfigError("duplicate propagation table")
    config = ServerConfig(sid, asn, region, vpc, tuple(endpoints), tuple(peers), tuple(propagations),
                          **{k: v for k, v in s.items() if k not in {"id", "asn", "region", "vpc_id"}})
    for key in ("poll_interval", "reconcile_interval", "stale_after"):
        number(getattr(config, key), key, 0.1, 3600)
    if config.stale_after < 2 * config.poll_interval:
        raise ConfigError("stale_after must be at least twice poll_interval")
    number(config.failback_delay, "failback_delay", 0, 3600)
    number(config.persist_duration, "persist_duration", 60, 300)
    number(config.port, "port", 0, 65535, True)
    address(config.listen, "listen")
    if not isinstance(config.persist_routes, bool):
        raise ConfigError("persist_routes must be boolean")
    if not isinstance(config.state_dir, str) or not Path(config.state_dir).is_absolute():
        raise ConfigError("state_dir must be an absolute path")
    if not isinstance(config.owner_tag, str) or not re.fullmatch(r"[A-Za-z0-9_./:-]{1,128}", config.owner_tag):
        raise ConfigError("invalid owner_tag")
    return config
