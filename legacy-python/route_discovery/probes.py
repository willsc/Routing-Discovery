"""Bounded TCP probes with an explicit path selector; no shell or DNS lookup."""

import asyncio
from dataclasses import dataclass
import ipaddress
import socket
import time

from .config import Candidate, Probe


@dataclass(frozen=True)
class Result:
    ok: bool
    latency_ms: float | None = None
    error: str | None = None


async def tcp_probe(probe: Probe, timeout: float) -> Result:
    started = time.monotonic()
    family = socket.AF_INET6 if ipaddress.ip_address(probe.host).version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.setblocking(False)
            if probe.device:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, probe.device.encode() + b"\0")
            if probe.mark is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, probe.mark)
            if probe.source:
                sock.bind((probe.source, 0))
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, (probe.host, probe.port)), timeout)
        return Result(True, (time.monotonic() - started) * 1000)
    except (OSError, TimeoutError) as exc:
        return Result(False, error=f"{type(exc).__name__}: {exc}")


async def candidate_probe(candidate: Candidate, timeout: float) -> Result:
    results = await asyncio.gather(*(tcp_probe(p, timeout) for p in candidate.probes))
    good = [r for r in results if r.ok]
    ok = len(good) >= candidate.quorum
    latency = max((r.latency_ms for r in good), default=None)
    errors = "; ".join(r.error for r in results if r.error)
    return Result(ok, latency, errors or None)
