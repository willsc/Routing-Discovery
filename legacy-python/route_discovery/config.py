"""Strict configuration: a typo in routing policy must never be ignored."""

from dataclasses import dataclass, field
import ipaddress
import math
from pathlib import Path
import re
import tomllib


class ConfigError(ValueError):
    pass


def check_keys(raw, allowed, where):
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected a table")
    unknown = raw.keys() - allowed
    if unknown:
        raise ConfigError(f"{where}: unknown keys: {', '.join(sorted(unknown))}")


def number(value, name, low=0, high=1e9, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name}: expected a number")
    if not math.isfinite(value) or not low <= value <= high or (integer and not isinstance(value, int)):
        raise ConfigError(f"{name}: expected {'integer' if integer else 'number'} in [{low}, {high}]")
    return value


def name(value, where):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
        raise ConfigError(f"{where}: use 1–64 letters, digits, dots, underscores or hyphens")
    return value


def address(value, where):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ConfigError(f"{where}: use a literal IP address (no DNS dependency)") from exc


@dataclass(frozen=True)
class Probe:
    host: str
    port: int
    source: str | None = None
    device: str | None = None
    mark: int | None = None
    # External path isolation is required for the AWS API backend.
    external_path: str | None = None


@dataclass(frozen=True)
class Candidate:
    id: str
    probes: tuple[Probe, ...]
    quorum: int = 1
    gateway: str | None = None
    device: str | None = None
    aws_target: str | None = None
    local_pref: int = 100
    as_path: tuple[int, ...] = ()
    med: int = 0
    cost: int = 0
    enabled: bool = True

    @property
    def rank(self):
        # Deliberate local policy: MED always compared across candidates.
        return (-self.local_pref, len(self.as_path), self.med, self.cost)


@dataclass(frozen=True)
class Route:
    prefix: str
    candidates: tuple[Candidate, ...]
    max_paths: int = 1
    preempt: bool = True
    all_down: str = "withdraw"


@dataclass(frozen=True)
class Health:
    interval: float = 1.0
    timeout: float = 0.3
    failures: int = 3
    successes: int = 3
    failback_delay: float = 10.0
    stale_after: float = 5.0
    dampening_half_life: float = 30.0
    dampening_penalty: float = 1000.0
    dampening_suppress: float = 2500.0
    dampening_reuse: float = 750.0
    dampening_max: float = 120.0


@dataclass(frozen=True)
class Backend:
    kind: str = "linux"
    table: int = 254
    protocol: int = 196
    metric: int = 100
    region: str | None = None
    route_table_id: str | None = None
    owner_tag: str = "route-discovery"
    owner_value: str = "managed"
    frr_tag: int = 186


@dataclass(frozen=True)
class Config:
    routes: tuple[Route, ...]
    health: Health = field(default_factory=Health)
    backend: Backend = field(default_factory=Backend)
    local_asn: int = 65000
    reconcile_interval: float = 1.0
    state_dir: str = "/var/lib/route-discovery"
    listen: str = "127.0.0.1"
    port: int = 9808


def load(path):
    try:
        with Path(path).open("rb") as stream:
            return parse(tomllib.load(stream))
    except (OSError, tomllib.TOMLDecodeError, TypeError, KeyError) as exc:
        raise ConfigError(str(exc)) from exc


def parse(raw):
    check_keys(raw, {"routes", "health", "backend", "daemon"}, "config")
    daemon = raw.get("daemon", {})
    check_keys(daemon, {"local_asn", "reconcile_interval", "state_dir", "listen", "port"}, "daemon")
    health_raw = raw.get("health", {})
    check_keys(health_raw, set(Health.__dataclass_fields__), "health")
    h = Health(**health_raw)
    for k in ("interval", "timeout", "stale_after", "dampening_half_life", "dampening_max"):
        number(getattr(h, k), f"health.{k}", 0.01, 86400)
    for k in ("failures", "successes"):
        number(getattr(h, k), f"health.{k}", 1, 1000, True)
    for k in ("failback_delay", "dampening_penalty", "dampening_suppress", "dampening_reuse"):
        number(getattr(h, k), f"health.{k}", 0, 1e6)
    if h.timeout > h.interval or h.stale_after <= h.interval + h.timeout:
        raise ConfigError("timeout must be <= interval; stale_after must exceed interval + timeout")
    if not 0 < h.dampening_reuse < h.dampening_suppress:
        raise ConfigError("dampening thresholds require 0 < reuse < suppress")
    b_raw = raw.get("backend", {})
    check_keys(b_raw, set(Backend.__dataclass_fields__), "backend")
    b = Backend(**b_raw)
    if b.kind not in {"linux", "aws", "frr"}:
        raise ConfigError("backend.kind must be linux, aws, or frr")
    number(b.table, "backend.table", 1, 2**32 - 1, True)
    if b.table in (253, 255):
        raise ConfigError("cannot manage Linux local/default tables")
    number(b.protocol, "backend.protocol", 1, 255, True)
    if b.kind == "linux" and b.protocol in (1, 2, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 42, 99, 186, 187, 188, 189, 192):
        raise ConfigError("choose an unused Linux route protocol, e.g. 196")
    number(b.metric, "backend.metric", 1, 2**32 - 1, True)
    number(b.frr_tag, "backend.frr_tag", 1, 2**32 - 1, True)
    if b.kind == "aws":
        if not isinstance(b.region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", b.region):
            raise ConfigError("AWS backend requires region")
        if not isinstance(b.route_table_id, str) or not re.fullmatch(r"rtb-[0-9a-f]{8,17}", b.route_table_id):
            raise ConfigError("AWS backend requires route_table_id")
        if not b.owner_tag or not b.owner_value:
            raise ConfigError("AWS route table ownership tag and value must be nonempty")
    asn = number(daemon.get("local_asn", 65000), "local_asn", 1, 2**32 - 1, True)
    routes = []
    prefixes = set()
    marks = set()
    entries = raw.get("routes", [])
    if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
        raise ConfigError("configure 1–256 routes")
    for r in entries:
        check_keys(r, {"prefix", "candidates", "max_paths", "preempt", "all_down"}, "route")
        try:
            net = ipaddress.ip_network(r["prefix"], strict=True)
        except (ValueError, KeyError) as exc:
            raise ConfigError("route.prefix must be a canonical IPv4/IPv6 network") from exc
        prefix = str(net)
        if prefix in prefixes:
            raise ConfigError(f"duplicate prefix {prefix}")
        prefixes.add(prefix)
        candidates = []
        ids = set()
        hops = set()
        c_entries = r.get("candidates", [])
        if not isinstance(c_entries, list) or not 1 <= len(c_entries) <= 32:
            raise ConfigError(f"{prefix}: configure 1–32 candidates")
        for c in c_entries:
            check_keys(c, set(Candidate.__dataclass_fields__), f"candidate in {prefix}")
            cid = name(c.get("id"), "candidate.id")
            if cid in ids:
                raise ConfigError(f"{prefix}: duplicate candidate {cid}")
            ids.add(cid)
            gateway = c.get("gateway")
            device = c.get("device")
            if b.kind in ("linux", "frr"):
                gateway = address(gateway, "gateway") if gateway is not None else None
                if gateway and ipaddress.ip_address(gateway).version != net.version:
                    raise ConfigError("gateway and destination families differ")
                if not isinstance(device, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", device) or device.startswith("-"):
                    raise ConfigError("Linux/FRR candidates need a valid interface name")
            target = c.get("aws_target")
            if b.kind == "aws" and (not isinstance(target, str) or not re.fullmatch(r"eni-[0-9a-f]{8,17}", target)):
                raise ConfigError("AWS candidates require an ENI aws_target")
            hop = (gateway, device, target)
            if hop in hops:
                raise ConfigError("candidate next hops must be distinct")
            hops.add(hop)
            probes = []
            p_entries = c.get("probes", [])
            if not isinstance(p_entries, list) or not 1 <= len(p_entries) <= 8:
                raise ConfigError(f"{cid}: configure 1–8 probes")
            candidate_marks = set()
            for p in p_entries:
                check_keys(p, set(Probe.__dataclass_fields__), "probe")
                host = address(p.get("host"), "probe.host")
                port = number(p.get("port"), "probe.port", 1, 65535, True)
                source = address(p["source"], "probe.source") if "source" in p else None
                if source and ipaddress.ip_address(source).version != ipaddress.ip_address(host).version:
                    raise ConfigError("probe source and host families differ")
                mark = p.get("mark")
                if mark is not None:
                    number(mark, "probe.mark", 1000, 30000, True)
                    if mark == b.table:
                        raise ConfigError("probe mark/table must differ from managed route table")
                    candidate_marks.add(mark)
                pdev = p.get("device", device)
                if pdev is not None and (not isinstance(pdev, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", pdev) or pdev.startswith("-")):
                    raise ConfigError("invalid probe.device")
                external = p.get("external_path")
                if b.kind in ("linux", "frr"):
                    if mark is None or ipaddress.ip_address(host).version != net.version or pdev != device:
                        raise ConfigError("Linux/FRR probes need mark, candidate device, and matching IP family")
                    if host == gateway:
                        raise ConfigError("probe an endpoint beyond the gateway to test forwarding")
                elif not isinstance(external, str) or not external.strip():
                    raise ConfigError("AWS probes require external_path documenting a path-specific endpoint/vantage point")
                probes.append(Probe(host, port, source, pdev, mark, external))
            if marks & candidate_marks:
                raise ConfigError("each candidate must have independent probe marks/tables")
            marks.update(candidate_marks)
            if len({(p.host, p.port, p.source, p.device, p.mark) for p in probes}) != len(probes):
                raise ConfigError("duplicate probes cannot count towards quorum")
            quorum = number(c.get("quorum", len(probes)), "quorum", 1, len(probes), True)
            attrs = {}
            for k, default in (("local_pref", 100), ("med", 0), ("cost", 0)):
                attrs[k] = number(c.get(k, default), k, 0, 2**32 - 1, True)
            path = c.get("as_path", [])
            if not isinstance(path, list) or len(path) > 255:
                raise ConfigError("as_path must be an array of <=255 ASNs")
            for value in path:
                number(value, "AS number", 1, 2**32 - 1, True)
            if not isinstance(c.get("enabled", True), bool):
                raise ConfigError("enabled must be a boolean")
            candidates.append(Candidate(cid, tuple(probes), quorum, gateway, device, target,
                                        as_path=tuple(path), enabled=c.get("enabled", True), **attrs))
        max_paths = number(r.get("max_paths", 1), "max_paths", 1, len(candidates), True)
        if b.kind == "aws" and max_paths != 1:
            raise ConfigError("AWS route-table backend supports one next hop per prefix")
        if b.kind == "linux" and net.version == 6 and max_paths > 1 and any(c.gateway is None for c in candidates):
            raise ConfigError("Linux IPv6 ECMP requires an explicit gateway on every candidate")
        all_down = r.get("all_down", "withdraw")
        allowed = {"withdraw", "retain"} | ({"unreachable"} if b.kind == "linux" else set())
        if all_down not in allowed:
            raise ConfigError(f"all_down must be one of {sorted(allowed)}")
        if not isinstance(r.get("preempt", True), bool):
            raise ConfigError("preempt must be a boolean")
        routes.append(Route(prefix, tuple(candidates), max_paths, r.get("preempt", True), all_down))
    interval = number(daemon.get("reconcile_interval", 1.0), "reconcile_interval", 0.05, 3600)
    listen = address(daemon.get("listen", "127.0.0.1"), "listen")
    port = number(daemon.get("port", 9808), "port", 0, 65535, True)
    state_dir = daemon.get("state_dir", "/var/lib/route-discovery")
    if not isinstance(state_dir, str) or not Path(state_dir).is_absolute():
        raise ConfigError("state_dir must be an absolute path")
    if sum(len(c.probes) for r in routes for c in r.candidates) > 1024:
        raise ConfigError("at most 1024 probes are supported per process")
    return Config(tuple(routes), h, b, asn, interval, state_dir, listen, port)
