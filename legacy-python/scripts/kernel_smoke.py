#!/usr/bin/env python3
"""Exercise real iproute2 commands in a new user+network namespace, never the host."""

import asyncio
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from route_discovery.backends import Linux, probe_plan, validate_probe_paths
from route_discovery.commands import run
from route_discovery.config import load
from route_discovery.policy import Decision


async def smoke():
    config = load(Path(__file__).resolve().parents[1] / "examples/linux.toml")
    await run("ip", "link", "set", "lo", "up")
    for device in ("wg-a", "wg-b"):
        await run("ip", "link", "add", device, "type", "dummy")
        await run("ip", "link", "set", device, "up")
    for line in probe_plan(config).splitlines():
        if line.startswith("ip "):
            await run(*line.split())
    await validate_probe_paths(config)
    backend = Linux(config)
    route = config.routes[0]
    for decision in (Decision("route", ("az-a",)), Decision("route", ("az-b",)),
                     Decision("route", ("az-a", "az-b")), Decision("unreachable"),
                     Decision("route", ("az-a",)), Decision("withdraw")):
        assert await backend.apply(route, decision), decision
        await validate_probe_paths(config)
    for index, device in enumerate(("wg-a", "wg-b"), 1):
        await run("ip", "-6", "addr", "add", f"2001:db8:{index}::1/64", "dev", device, "nodad")
    route6 = replace(route, prefix="2001:db8:20::/64", candidates=tuple(
        replace(c, gateway=f"2001:db8:{i}::2") for i, c in enumerate(route.candidates, 1)))
    for decision in (Decision("route", ("az-a",)), Decision("route", ("az-a", "az-b")),
                     Decision("unreachable"), Decision("withdraw")):
        assert await backend.apply(route6, decision), decision
    print("PASS: real IPv4/IPv6 install, failover, ECMP, unreachable, withdrawal, and probe isolation")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        original = str(os.stat("/proc/self/ns/net").st_ino)
        result = subprocess.run(["unshare", "--user", "--map-root-user", "--net", sys.executable,
                                 str(Path(__file__).resolve()), "--isolated", original])
        raise SystemExit(result.returncode)
    if len(sys.argv) != 3 or sys.argv[1] != "--isolated" or str(os.stat("/proc/self/ns/net").st_ino) == sys.argv[2]:
        raise SystemExit("refusing to run outside a private network namespace")
    asyncio.run(smoke())
