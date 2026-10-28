"""Reconcile observed state, never flush a table or assume a write succeeded."""

import asyncio
from dataclasses import dataclass
import ipaddress
import json

from .commands import BackendError, run


@dataclass(frozen=True)
class Observed:
    paths: tuple[str, ...] = ()
    action: str = "withdraw"
    usable: bool = True


def family(prefix):
    return "-6" if ipaddress.ip_network(prefix).version == 6 else "-4"


def wanted(decision):
    return Observed(decision.paths, decision.action)


def route_type(record):
    # ip -N prints numeric route types as well as numeric protocol/table IDs.
    value = str(record.get("type", "unicast"))
    return {"1": "unicast", "7": "unreachable"}.get(value, value)


class DryRun:
    """Isolated in-memory FIB: does not read credentials, invoke ip, or call AWS."""
    def __init__(self):
        self.routes = {}
        self.changes = []

    async def current(self, route):
        return self.routes.get(route.prefix, Observed())

    async def apply(self, route, decision):
        if decision.action == "hold":
            return True
        value = wanted(decision)
        if await self.current(route) != value:
            self.routes[route.prefix] = value
            self.changes.append((route.prefix, decision))
        return True


class Linux:
    def __init__(self, config, runner=run):
        self.config = config
        self.b = config.backend
        self.run = runner

    async def current(self, route):
        try:
            output = await self.run("ip", family(route.prefix), "-N", "-j", "route", "show",
                                    "table", str(self.b.table), "exact", route.prefix)
        except BackendError as exc:
            if "FIB table does not exist" in str(exc):
                return Observed()
            raise
        records = json.loads(output)
        if not records:
            return Observed()
        if len(records) != 1:
            raise BackendError(f"{route.prefix}: competing routes; refusing to change them")
        record = records[0]
        if str(record.get("protocol")) != str(self.b.protocol) or record.get("metric", 0) != self.b.metric:
            raise BackendError(f"{route.prefix}: route is not owned by this daemon (protocol/metric)")
        if route_type(record) == "unreachable":
            return Observed(action="unreachable")
        if route_type(record) != "unicast" or "nhid" in record:
            raise BackendError(f"{route.prefix}: unsupported existing route representation")
        hops = record.get("nexthops", [record])
        ids = []
        for hop in hops:
            matches = [c.id for c in route.candidates if c.gateway == hop.get("gateway") and c.device == hop.get("dev")]
            if len(matches) != 1 or hop.get("weight", 1) != 1 or hop.get("encap"):
                raise BackendError(f"{route.prefix}: unconfigured next hop or route attributes")
            ids.extend(matches)
        return Observed(tuple(sorted(ids)), "route")

    async def apply(self, route, decision):
        before = await self.current(route)
        if decision.action == "hold" or before == wanted(decision):
            return True
        args = ["ip", family(route.prefix), "route"]
        if decision.action == "withdraw":
            args += ["del"]
            if before.action == "unreachable":
                args += ["unreachable"]
            args += [route.prefix]
        else:
            args += ["replace"]
            if decision.action == "unreachable":
                args += ["unreachable"]
            args += [route.prefix]
        args += ["table", str(self.b.table), "proto", str(self.b.protocol), "metric", str(self.b.metric)]
        if decision.action == "route":
            selected = [c for c in route.candidates if c.id in decision.paths]
            for c in selected:
                if len(selected) > 1:
                    args += ["nexthop"]
                if c.gateway:
                    args += ["via", c.gateway]
                args += ["dev", c.device]
                if len(selected) > 1:
                    args += ["weight", "1"]
        await self.run(*args)
        return await self.current(route) == wanted(decision)


class AWS:
    """Single writer only: EC2 route updates have no compare-and-swap primitive."""
    def __init__(self, config, client=None):
        self.b = config.backend
        if client is None:
            try:
                import boto3
                from botocore.config import Config
            except ImportError as exc:
                raise BackendError("Install route-discovery[aws] for the AWS backend") from exc
            client = boto3.client("ec2", region_name=self.b.region, config=Config(
                connect_timeout=2, read_timeout=3, retries={"mode": "standard", "total_max_attempts": 2}))
        self.client = client

    def destination(self, route):
        key = "DestinationIpv6CidrBlock" if family(route.prefix) == "-6" else "DestinationCidrBlock"
        return {key: route.prefix}

    async def current(self, route):
        response = await asyncio.to_thread(self.client.describe_route_tables, RouteTableIds=[self.b.route_table_id])
        tables = response.get("RouteTables", [])
        if len(tables) != 1 or tables[0].get("RouteTableId") != self.b.route_table_id:
            raise BackendError("AWS route table is missing or unexpected")
        table = tables[0]
        tags = {t["Key"]: t["Value"] for t in table.get("Tags", [])}
        if tags.get(self.b.owner_tag) != self.b.owner_value:
            raise BackendError("AWS route table is missing its required ownership tag")
        key, prefix = next(iter(self.destination(route).items()))
        found = [r for r in table.get("Routes", []) if r.get(key) == prefix]
        if not found:
            return Observed()
        if len(found) != 1:
            raise BackendError("unexpected duplicate AWS routes")
        record = found[0]
        if record.get("Origin") != "CreateRoute" or record.get("GatewayId") == "local":
            raise BackendError(f"{prefix}: refusing to modify a local or propagated AWS route")
        matches = [c.id for c in route.candidates if c.aws_target == record.get("NetworkInterfaceId")]
        if len(matches) != 1:
            raise BackendError(f"{prefix}: existing AWS target is outside the configured allowlist")
        return Observed(tuple(matches), "route", record.get("State") == "active")

    async def apply(self, route, decision):
        before = await self.current(route)
        if decision.action == "hold" or before == wanted(decision):
            return True
        args = {"RouteTableId": self.b.route_table_id, **self.destination(route)}
        if decision.action == "withdraw":
            response = await asyncio.to_thread(self.client.delete_route, **args)
        else:
            candidate = next(c for c in route.candidates if c.id == decision.paths[0])
            args["NetworkInterfaceId"] = candidate.aws_target
            method = self.client.create_route if before.action == "withdraw" else self.client.replace_route
            response = await asyncio.to_thread(method, **args)
        if response.get("Return") is False:
            raise BackendError("AWS rejected route operation")
        # Eventual consistency: leave desired state pending until a subsequent read agrees.
        return await self.current(route) == wanted(decision)


class FRR:
    """Own tagged static routes; FRR owns the BGP/BFD sessions and advertisements."""
    def __init__(self, config, runner=run):
        self.b = config.backend
        self.run = runner

    def command(self, route, candidate):
        parts = ["ipv6" if family(route.prefix) == "-6" else "ip", "route", route.prefix]
        if candidate.gateway:
            parts.append(candidate.gateway)
        parts += [candidate.device, "tag", str(self.b.frr_tag)]
        return " ".join(parts)

    async def current(self, route):
        config = await self.run("vtysh", "-c", "show running-config")
        start = ("ipv6" if family(route.prefix) == "-6" else "ip") + " route " + route.prefix + " "
        expected = {self.command(route, c): c.id for c in route.candidates}
        ids = []
        for line in config.splitlines():
            # Restrict to global static routes; VRF commands start with whitespace.
            if not line.startswith(start):
                continue
            if line not in expected:
                raise BackendError(f"{route.prefix}: unowned or unsupported FRR static route")
            ids.append(expected[line])
        return Observed(tuple(sorted(ids)), "route" if ids else "withdraw")

    async def apply(self, route, decision):
        before = await self.current(route)
        if decision.action == "hold" or before == wanted(decision):
            return True
        # Add first, then remove. Changes are not atomic in FRR; transient ECMP is possible.
        add = set(decision.paths) - set(before.paths)
        remove = set(before.paths) - set(decision.paths)
        commands = ["configure terminal"]
        commands.extend(self.command(route, c) for c in route.candidates if c.id in add)
        commands.extend("no " + self.command(route, c) for c in route.candidates if c.id in remove)
        commands.append("end")
        args = ["vtysh"]
        for command in commands:
            args += ["-c", command]
        output = await self.run(*args)
        if any(line.lstrip().startswith("%") for line in output.splitlines()):
            raise BackendError(f"FRR rejected route commands: {output.strip()}")
        # Verifies static configuration, not BGP convergence or kernel installation.
        return await self.current(route) == wanted(decision)


def make_backend(config, apply):
    if not apply:
        return DryRun()
    return {"linux": Linux, "aws": AWS, "frr": FRR}[config.backend.kind](config)


def probe_plan(config):
    """Return a reviewable shell script. Never alter the operator's policy routing."""
    if config.backend.kind == "aws":
        raise BackendError("AWS probe paths must be provisioned at their external vantage points")
    lines = ["#!/bin/sh", "set -eu", "# Reserve each listed table and rule priority exclusively for probes.",
             "# Run once after checking for collisions; Linux permits duplicate policy rules."]
    seen = set()
    for route in config.routes:
        for c in route.candidates:
            for p in c.probes:
                fam = family(route.prefix)
                key = (fam, p.mark)
                if key not in seen:
                    seen.add(key)
                    lines += [f"ip {fam} route replace unreachable default table {p.mark} proto 196 metric 32760",
                              f"ip {fam} rule add priority {p.mark} fwmark {p.mark}/0xffffffff lookup {p.mark}"]
                    if c.gateway:
                        gateway_prefix = c.gateway + ("/128" if fam == "-6" else "/32")
                        lines.append(f"ip {fam} route replace {gateway_prefix} dev {c.device} scope link table {p.mark} proto 196")
                via = f" via {c.gateway}" if c.gateway else ""
                host_prefix = p.host + ("/128" if fam == "-6" else "/32")
                lines.append(f"ip {fam} route replace {host_prefix}{via} dev {c.device} table {p.mark} proto 196")
    return "\n".join(lines) + "\n"


async def validate_probe_paths(config, runner=run):
    if config.backend.kind == "aws":
        return  # External vantage-point correctness is an operator responsibility.
    for route in config.routes:
        for c in route.candidates:
            for p in c.probes:
                args = ["ip", family(route.prefix), "-N", "-j", "route", "get", p.host,
                        "mark", str(p.mark), "oif", p.device]
                if p.source:
                    args += ["from", p.source]
                rows = json.loads(await runner(*args))
                if len(rows) != 1 or str(rows[0].get("table")) != str(p.mark) or rows[0].get("dev") != c.device or rows[0].get("gateway") != c.gateway:
                    raise BackendError(f"{route.prefix}/{c.id}: probe {p.host} is not pinned to its configured path/table")
                # A terminal route prevents fall-through if a host route disappears.
                fallback = json.loads(await runner("ip", family(route.prefix), "-N", "-j", "route", "show",
                                                   "table", str(p.mark), "exact", "default"))
                if len(fallback) != 1 or route_type(fallback[0]) != "unreachable":
                    raise BackendError(f"probe table {p.mark} needs an unreachable default; observed {fallback!r}")
