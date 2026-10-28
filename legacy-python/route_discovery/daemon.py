import asyncio
from dataclasses import asdict
import json
import logging
import random
import time

from .backends import validate_probe_paths
from .policy import Policy
from .probes import candidate_probe
from .supervision import notify


LOG = logging.getLogger("route_discovery")


class Daemon:
    def __init__(self, config, backend, store=None, apply=False, probe=candidate_probe, validate=validate_probe_paths):
        self.config = config
        self.backend = backend
        self.store = store
        self.apply = apply
        self.probe = probe
        self.validate = validate
        self.policy = Policy(config, time.monotonic())
        self.stop = asyncio.Event()
        self.write_lock = asyncio.Lock()
        self.route_status = {r.prefix: {"converged": False, "error": None, "decision": None, "observed": None}
                             for r in config.routes}
        self.probe_path_errors = {}
        self.last_loop = time.monotonic()
        self.changes = 0
        self.errors = 0

    async def probe_loop(self, route, candidate):
        state = self.policy.health[route.prefix, candidate.id]
        h = self.config.health
        deadline = time.monotonic()
        while not self.stop.is_set():
            # Verify pinning on each sample so routing drift cannot falsely revive a path.
            try:
                if self.apply and self.config.backend.kind != "aws":
                    from dataclasses import replace
                    scoped = replace(self.config, routes=(replace(route, candidates=(candidate,)),))
                    await self.validate(scoped)
                self.probe_path_errors.pop((route.prefix, candidate.id), None)
                result = await self.probe(candidate, h.timeout)
                state.observe(result.ok, time.monotonic(), h, result.error, result.latency_ms)
            except Exception as exc:
                self.probe_path_errors[route.prefix, candidate.id] = str(exc)
                state.observe(False, time.monotonic(), h, str(exc))
                LOG.error("probe_error prefix=%s path=%s error=%s", route.prefix, candidate.id, exc)
            deadline += h.interval
            now = time.monotonic()
            if deadline < now:
                deadline = now + h.interval
            await self.sleep(deadline - now)

    async def sleep(self, delay):
        try:
            await asyncio.wait_for(self.stop.wait(), max(0.001, delay))
        except TimeoutError:
            pass

    async def reconcile_once(self, route):
        status = self.route_status[route.prefix]
        async with self.write_lock:
            observed = await self.backend.current(route)
            self.policy.installed[route.prefix] = observed.paths if observed.usable else ()
            status["observed"] = asdict(observed)
            decision = self.policy.select(route, time.monotonic())
            previous = status["decision"]
            status["decision"] = asdict(decision)
            # HOLD intentionally leaves a route in place, even if its target is unhealthy.
            if decision.action == "hold":
                status["converged"] = False
                status["error"] = None
                return
            if previous != status["decision"]:
                LOG.info("route_decision prefix=%s action=%s paths=%s reason=%s",
                         route.prefix, decision.action, decision.paths, decision.reason)
            converged = await self.backend.apply(route, decision)
            status["converged"] = converged
            status["error"] = None if converged else "waiting for backend convergence"
            if converged:
                self.policy.commit(route, decision)
                status["observed"] = {"paths": list(decision.paths), "action": decision.action, "usable": True}
                if observed.paths != decision.paths or observed.action != decision.action or not observed.usable:
                    self.changes += 1

    async def route_loop(self, route):
        failures = 0
        while not self.stop.is_set():
            try:
                await self.reconcile_once(route)
                failures = 0 if self.route_status[route.prefix]["converged"] else min(failures + 1, 5)
            except Exception as exc:
                failures = min(failures + 1, 5)
                self.errors += 1
                self.route_status[route.prefix].update(converged=False, error=str(exc))
                LOG.error("route_error prefix=%s error=%s", route.prefix, exc)
            base = self.config.reconcile_interval
            delay = min(30.0, base * 2 ** failures) if failures else base
            await self.sleep(delay * random.uniform(0.9, 1.1))

    def snapshot(self):
        now = time.monotonic()
        routes = {}
        for route in self.config.routes:
            paths = {}
            for c in route.candidates:
                h = self.policy.health[route.prefix, c.id]
                eligible = h.eligible(now, self.config.health) and c.enabled and self.config.local_asn not in c.as_path
                paths[c.id] = {"state": h.state, "eligible": eligible, "penalty": round(h.penalty, 3),
                               "suppressed": h.suppressed_since is not None, "last_error": h.last_error,
                               "latency_ms": h.latency_ms, "sample_age": None if h.last_sample is None else now - h.last_sample}
            routes[route.prefix] = {**self.route_status[route.prefix], "paths": paths}
        ready = all(r["converged"] and r["decision"] and r["decision"]["action"] == "route"
                    and all(r["paths"][cid]["eligible"] for cid in r["decision"]["paths"]) for r in routes.values())
        live = now - self.last_loop < max(5, self.config.health.stale_after)
        return {"mode": "apply" if self.apply else "dry-run", "backend": self.config.backend.kind,
                "ready": ready, "live": live, "changes": self.changes, "errors": self.errors, "routes": routes}

    def metrics(self):
        snap = self.snapshot()
        lines = [f"route_discovery_ready {int(snap['ready'])}", f"route_discovery_changes_total {self.changes}",
                 f"route_discovery_errors_total {self.errors}"]
        for prefix, route in snap["routes"].items():
            selected = (route["observed"] or {}).get("paths", ())
            for cid, state in route["paths"].items():
                labels = f'prefix="{prefix}",path="{cid}"'
                lines += [f"route_discovery_path_up{{{labels}}} {int(state['eligible'])}",
                          f"route_discovery_path_selected{{{labels}}} {int(cid in selected)}",
                          f"route_discovery_path_penalty{{{labels}}} {state['penalty']}"]
        return "\n".join(lines) + "\n"

    async def http(self, reader, writer):
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            first = request.split(b"\r\n", 1)[0].decode("ascii").split()
            if len(first) != 3 or first[0] != "GET":
                code, content, body = 405, "text/plain", "GET only\n"
            elif first[1] == "/metrics":
                code, content, body = 200, "text/plain; version=0.0.4", self.metrics()
            elif first[1] in ("/healthz", "/readyz", "/status"):
                snap = self.snapshot()
                code = 503 if (first[1] == "/healthz" and not snap["live"]) or (first[1] == "/readyz" and not snap["ready"]) else 200
                content, body = "application/json", json.dumps(snap, allow_nan=False)
            else:
                code, content, body = 404, "text/plain", "not found\n"
            data = body.encode()
            writer.write(f"HTTP/1.1 {code} {'OK' if code == 200 else 'Error'}\r\nContent-Type: {content}\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)
            await asyncio.wait_for(writer.drain(), 2)
        except (TimeoutError, OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def heartbeat(self):
        last_save = 0.0
        while not self.stop.is_set():
            self.last_loop = time.monotonic()
            notify("WATCHDOG=1")
            if self.store and self.last_loop - last_save >= 5:
                self.store.save(self.policy, self.last_loop)
                last_save = self.last_loop
            await self.sleep(0.5)

    async def run(self):
        if self.store:
            self.store.restore(self.policy, time.monotonic())
        if self.apply:
            await self.validate(self.config)
        server = await asyncio.start_server(self.http, self.config.listen, self.config.port, limit=8192)
        notify("READY=1")
        try:
            async with server, asyncio.TaskGroup() as group:
                group.create_task(self.heartbeat())
                for route in self.config.routes:
                    for c in route.candidates:
                        group.create_task(self.probe_loop(route, c))
                    group.create_task(self.route_loop(route))
                await self.stop.wait()
                # Let route writes finish: cancelling an AWS thread cannot cancel its API request.
                # Probe loops and writer loops observe stop at their next bounded wait.
        finally:
            notify("STOPPING=1")
            try:
                if self.store:
                    self.store.save(self.policy, time.monotonic())
            finally:
                if self.apply and self.config.backend.kind == "frr":
                    from .policy import Decision
                    for route in self.config.routes:
                        try:
                            await self.backend.apply(route, Decision("withdraw", reason="daemon shutdown"))
                        except Exception:
                            LOG.exception("failed to withdraw FRR route on shutdown: %s", route.prefix)
            LOG.info("stopped; Linux/AWS routes retained; FRR routes withdrawn where possible")
