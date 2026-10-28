"""FRR JSON adapter. Unknown/malformed output is a source failure, never an empty RIB."""

import asyncio
import ipaddress
import json
import re

from ..commands import BackendError, run
from .config import permits
from .rib import LearnedRoute, Snapshot


def uint(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**32 - 1:
        raise ValueError(f"invalid {field}")
    return value


def parse_snapshot(config, endpoint, data):
    try:
        if not isinstance(data, dict) or not isinstance(data.get("summary"), dict):
            raise ValueError("missing BGP summary")
        peers = [p for p in config.peers if p.endpoint == endpoint.id]
        states = {}
        peer_map = {p.address: p for p in peers}
        bfd = data.get("bfd", [])
        if not isinstance(bfd, list) or any(not isinstance(row, dict) for row in bfd):
            raise ValueError("invalid BFD peer list")
        tables = {}
        families = {ipaddress.ip_network(prefix).version for p in peers for prefix in p.allowed_prefixes}
        for version in families:
            summary = data["summary"].get(f"ipv{version}Unicast")
            if not isinstance(summary, dict) or not isinstance(summary.get("peers"), dict):
                raise ValueError(f"missing IPv{version} peer summary")
            rib = data.get(f"ipv{version}")
            if not isinstance(rib, dict) or not isinstance(rib.get("routes"), dict):
                raise ValueError(f"missing IPv{version} routes object")
            tables[version] = rib["routes"]
        for peer in peers:
            versions = {ipaddress.ip_network(prefix).version for prefix in peer.allowed_prefixes}
            af_state = {}
            for version in versions:
                record = data["summary"][f"ipv{version}Unicast"]["peers"].get(peer.address)
                # Missing configured peers are a configuration fault, not a healthy empty RIB.
                if not isinstance(record, dict) or "state" not in record or "remoteAs" not in record:
                    raise ValueError(f"missing configured peer {peer.id} in IPv{version} summary")
                af_state[version] = record["state"] == "Established" and record["remoteAs"] == peer.asn
            bfd_rows = [r for r in bfd if r.get("peer") == peer.address and
                        r.get("local", endpoint.address) == endpoint.address and r.get("vrf", "default") == "default"]
            bfd_up = not peer.bfd or (len(bfd_rows) == 1 and bfd_rows[0].get("status") == "up")
            states[peer.id] = {"up": any(af_state.values()) and bfd_up, "bgp": af_state,
                               "bfd": "up" if peer.bfd and bfd_up else "down" if peer.bfd else "disabled",
                               "reason": "available" if any(af_state.values()) and bfd_up else "BGP/BFD unavailable"}
        routes, rejected, counts = [], [], {p.id: set() for p in peers}
        for version, table in tables.items():
            for prefix, paths in table.items():
                net = ipaddress.ip_network(prefix, strict=True)
                if net.version != version or not isinstance(paths, list):
                    raise ValueError("invalid routes table schema")
                for path in paths:
                    if not isinstance(path, dict):
                        raise ValueError("invalid route entry")
                    peer = peer_map.get(path.get("peerId"))
                    if peer is None:
                        continue  # Local or unconfigured peer routes cannot enter this controller.
                    counts[peer.id].add(prefix)
                    reason = None
                    try:
                        if not states[peer.id]["up"] or not states[peer.id]["bgp"].get(version, False):
                            raise ValueError("peer unavailable")
                        if path.get("valid") is not True or any(path.get(k) for k in ("stale", "removed", "suppressed", "damped")):
                            raise ValueError("route invalid, stale or suppressed")
                        if not permits(prefix, peer.allowed_prefixes):
                            raise ValueError("prefix outside peer allowlist")
                        raw_as = path.get("path")
                        if not isinstance(raw_as, str) or not re.fullmatch(r"\d+(?: +\d+)*", raw_as):
                            raise ValueError("only nonempty AS_SEQUENCE paths in asplain notation are supported")
                        as_path = tuple(uint(int(a), "AS number") for a in raw_as.split())
                        if len(as_path) > 255 or 0 in as_path or as_path[0] != peer.asn or config.asn in as_path:
                            raise ValueError("AS path loop, first-AS mismatch or invalid AS path")
                        next_hops = path.get("nexthops")
                        if not isinstance(next_hops, list):
                            raise ValueError("missing next hops")
                        hops = {str(ipaddress.ip_address(h["ip"])) for h in next_hops if isinstance(h, dict) and "ip" in h}
                        allowed = sorted(hops & set(peer.next_hops))
                        if not allowed:
                            raise ValueError("next hop outside the peer's configured ENI addresses")
                        med = uint(path.get("metric", 0), "MED")
                        routes.append(LearnedRoute(prefix, peer.id, endpoint.id, peer.eni, allowed[0],
                                                   as_path, med, peer.local_pref))
                    except (ValueError, KeyError, TypeError) as exc:
                        reason = str(exc)
                    if reason:
                        rejected.append({"prefix": prefix, "peer": peer.id, "reason": reason})
        over = {p.id for p in peers if len(counts[p.id]) > p.max_prefixes}
        for pid in over:
            states[pid].update(up=False, reason="maximum prefix limit exceeded")
            rejected.append({"peer": pid, "reason": "maximum prefix limit exceeded; all peer routes rejected"})
        routes = [r for r in routes if r.peer not in over]
        # Add-path routes with the same mapped next hop have one deterministic local representative.
        unique = {}
        for route in sorted(routes, key=lambda r: (r.rank, r.as_path)):
            unique.setdefault(route.key, route)
        return Snapshot(tuple(unique.values()), states, tuple(rejected))
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise BackendError(f"{endpoint.id}: invalid FRR snapshot: {exc}") from exc


class FRRSource:
    def __init__(self, config, runner=run):
        self.config = config
        self.run = runner

    async def read(self, endpoint):
        async def query(command):
            output = await self.run("vtysh", "--vty_socket", endpoint.socket_dir, "-c", command, timeout=3)
            try:
                return json.loads(output)
            except ValueError as exc:
                raise BackendError(f"{endpoint.id}: non-JSON response for {command}") from exc

        peers = [p for p in self.config.peers if p.endpoint == endpoint.id]
        versions = sorted({ipaddress.ip_network(prefix).version for p in peers for prefix in p.allowed_prefixes})
        before = await query("show bgp summary json")
        values = await asyncio.gather(*(query(f"show bgp ipv{v} unicast json") for v in versions))
        bfd = await query("show bfd peers json") if any(p.bfd for p in peers) else []
        after = await query("show bgp summary json")
        # Detect a session change during the sample. This is polling, not an atomic FRR snapshot.
        for version in versions:
            key = f"ipv{version}Unicast"
            for peer in peers:
                a = before.get(key, {}).get("peers", {}).get(peer.address, {})
                b = after.get(key, {}).get("peers", {}).get(peer.address, {})
                fields = ("state", "remoteAs", "peerUptimeEstablishedEpoch")
                if any(a.get(f) != b.get(f) for f in fields):
                    raise BackendError(f"{endpoint.id}/{peer.id}: BGP session changed during snapshot")
        data = {"summary": after, "bfd": bfd, **{f"ipv{v}": value for v, value in zip(versions, values)}}
        return parse_snapshot(self.config, endpoint, data)


def render(config, endpoint_id):
    endpoint = next((e for e in config.endpoints if e.id == endpoint_id), None)
    if endpoint is None:
        raise ValueError("unknown endpoint")
    peers = [p for p in config.peers if p.endpoint == endpoint_id]
    lines = ["! Dedicated FRR instance for route-discovery route-server endpoint " + endpoint.id,
             "! Run zebra/bgpd/bfdd with this endpoint's socket directory and listen address.",
             "route-map RDS-DENY-OUT deny 10", "!"]
    for index, peer in enumerate(peers, 1):
        for version in (4, 6):
            cmd = "ip" if version == 4 else "ipv6"
            prefixes = [p for p in peer.allowed_prefixes if ipaddress.ip_network(p).version == version]
            for n, prefix in enumerate(prefixes, 1):
                maximum = 32 if version == 4 else 128
                length = "" if ipaddress.ip_network(prefix).prefixlen == maximum else f" le {maximum}"
                lines.append(f"{cmd} prefix-list RDS-P{index}-V{version} seq {n * 10} permit {prefix}{length}")
            if prefixes:
                lines += [f"route-map RDS-P{index}-V{version} permit 10",
                          f" match {cmd} address prefix-list RDS-P{index}-V{version}", f" set local-preference {peer.local_pref}", "!"]
    lines += [f"router bgp {config.asn}", f" bgp router-id {endpoint.router_id}", " no bgp default ipv4-unicast",
              " bgp bestpath as-path multipath-relax", " bgp always-compare-med"]
    for peer in peers:
        lines += [f" neighbor {peer.address} remote-as {peer.asn}", f" neighbor {peer.address} update-source {endpoint.address}",
                  f" neighbor {peer.address} timers 3 9"]
        if peer.bfd:
            lines.append(f" neighbor {peer.address} bfd")
    for version in (4, 6):
        active = [(i, p) for i, p in enumerate(peers, 1) if any(ipaddress.ip_network(n).version == version for n in p.allowed_prefixes)]
        if not active:
            continue
        lines.append(f" address-family ipv{version} unicast")
        for index, peer in active:
            lines += [f"  neighbor {peer.address} activate", f"  neighbor {peer.address} route-map RDS-P{index}-V{version} in",
                      f"  neighbor {peer.address} route-map RDS-DENY-OUT out", f"  neighbor {peer.address} maximum-prefix {peer.max_prefixes}"]
        lines.append(" exit-address-family")
    # Last: FRR 8.x warns if -n/-l already selected no-rib, which can reset file parsing context.
    lines.append(" bgp no-rib")
    return "\n".join(lines) + "\n"
