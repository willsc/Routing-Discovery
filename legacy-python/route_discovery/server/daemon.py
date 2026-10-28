import asyncio
import logging
import random
import time

from ..daemon import Daemon as HTTPMixin
from ..supervision import notify
from .frr import FRRSource
from .propagation import Propagator
from .rib import RIB


LOG = logging.getLogger("route_discovery.server")


class RouteServer:
    # Reuse the read-only HTTP handler and stop-aware timer, not the static route policy.
    http = HTTPMixin.http
    sleep = HTTPMixin.sleep

    def __init__(self, config, journal, apply=False, source=None, client=None):
        self.config = config
        self.journal = journal
        self.apply = apply
        self.source = source or FRRSource(config)
        self.rib = RIB(config)
        self.rib.selected = journal.load_fib(config)
        self.propagator = Propagator(config, journal, client, apply)
        self.stop = asyncio.Event()
        self.errors = {}
        self.started = time.monotonic()
        self.last_loop = self.started
        self.attempted = set()
        self.generation = 0
        self.desired = {}
        self.reconciled_generation = -1

    async def endpoint_loop(self, endpoint):
        while not self.stop.is_set():
            try:
                snapshot = await self.source.read(endpoint)
                self.rib.update(endpoint.id, snapshot, time.monotonic())
                self.errors.pop(endpoint.id, None)
            except Exception as exc:
                self.errors[endpoint.id] = str(exc)
                LOG.error("endpoint_error endpoint=%s error=%s", endpoint.id, exc)
            self.attempted.add(endpoint.id)
            await self.sleep(self.config.poll_interval)

    def selection(self):
        if len(self.attempted) < len(self.config.endpoints) and time.monotonic() - self.started < self.config.stale_after:
            return False
        selected = self.rib.select(time.monotonic())
        if selected != self.desired:
            self.desired = selected
            self.generation += 1
            self.journal.save_fib(selected)
            LOG.info("fib_change generation=%s prefixes=%s persisted=%s", self.generation, len(selected), self.rib.persisted)
        return True

    async def control_loop(self):
        delay = self.config.reconcile_interval
        while not self.stop.is_set():
            try:
                if self.selection():
                    generation = self.generation
                    converged = await self.propagator.reconcile(self.desired.copy(), lambda: generation == self.generation and not self.stop.is_set())
                    if converged and generation == self.generation:
                        self.reconciled_generation = generation
                    delay = self.config.reconcile_interval if converged else min(30, delay * 2)
            except Exception as exc:
                self.errors["propagation"] = str(exc)
                LOG.error("propagation_error error=%s", exc)
                delay = min(30, delay * 2)
            else:
                self.errors.pop("propagation", None)
            await self.sleep(delay * random.uniform(0.9, 1.1))

    async def heartbeat(self):
        while not self.stop.is_set():
            self.last_loop = time.monotonic()
            self.selection()  # Invalidate slow AWS passes when BGP changes or observations expire.
            notify("WATCHDOG=1")
            await self.sleep(min(0.5, self.config.poll_interval))

    def snapshot(self):
        view = self.rib.view(time.monotonic())
        any_peer = any(p["up"] for p in view["peers"].values())
        ready = (any_peer and not self.rib.persisted and not self.errors and
                 all(e["fresh"] for e in view["endpoints"].values()) and
                 self.reconciled_generation == self.generation and bool(self.propagator.status) and
                 all(p["converged"] for p in self.propagator.status.values()))
        return {"mode": "apply" if self.apply else "dry-run", "backend": "route-server", "id": self.config.id,
                "vpc": self.config.vpc_id, "live": time.monotonic() - self.last_loop < 5,
                "ready": ready, "generation": self.generation, "source_errors": self.errors,
                **view, "propagations": self.propagator.status}

    def metrics(self):
        status = self.snapshot()
        lines = [f"route_server_ready {int(status['ready'])}", f"route_server_rib_paths {len(status['rib'])}",
                 f"route_server_fib_prefixes {len(status['fib'])}", f"route_server_persisted {int(status['persisted'])}",
                 f"route_server_changes_total {self.propagator.changes}", f"route_server_write_errors_total {self.propagator.failures}"]
        for peer, state in status["peers"].items():
            lines.append(f'route_server_peer_up{{peer="{peer}"}} {int(state["up"])}')
        for table, state in status["propagations"].items():
            lines.append(f'route_server_propagation_converged{{table="{table}"}} {int(state["converged"])}')
        return "\n".join(lines) + "\n"

    async def run(self):
        await self.propagator.verify_targets()
        server = await asyncio.start_server(self.http, self.config.listen, self.config.port, limit=8192)
        notify("READY=1")
        try:
            async with server, asyncio.TaskGroup() as group:
                group.create_task(self.heartbeat())
                group.create_task(self.control_loop())
                for endpoint in self.config.endpoints:
                    group.create_task(self.endpoint_loop(endpoint))
                await self.stop.wait()
        finally:
            notify("STOPPING=1")
            self.journal.save_fib(self.rib.selected)
            LOG.info("route server stopped; VPC routes retained for supervised restart")
