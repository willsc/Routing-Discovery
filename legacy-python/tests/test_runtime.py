import asyncio
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import time
import unittest

from route_discovery.backends import DryRun
from route_discovery.commands import BackendError
from route_discovery.config import Probe
from route_discovery.daemon import Daemon
from route_discovery.policy import Policy
from route_discovery.probes import tcp_probe, candidate_probe
from route_discovery.probes import Result
from route_discovery.state import StateStore
from .helpers import configuration


class StateTests(unittest.TestCase):
    def test_single_writer_and_persistent_dampening(self):
        config = configuration()
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(directory)
            store.acquire()
            second = StateStore(directory)
            with self.assertRaises(BackendError):
                second.acquire()
            policy = Policy(config)
            state = policy.health[config.routes[0].prefix, "primary"]
            state.penalty = 3000
            state.penalty_at = 100
            state.suppressed_since = 99
            state.state = "up"
            store.save(policy, 100)
            restored = Policy(config)
            store.restore(restored, 200)
            value = restored.health[config.routes[0].prefix, "primary"]
            self.assertGreater(value.penalty, 2900)
            self.assertIsNotNone(value.suppressed_since)
            self.assertEqual(value.state, "unknown")
            self.assertIsNone(value.last_sample)
            store.close()
            second.acquire()
            second.close()

    def test_corrupt_checkpoint_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "dampening.json").write_text('{"version": 999}')
            with self.assertRaises(BackendError):
                StateStore(directory).restore(Policy(configuration()), 0)


class SocketTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []

    async def asyncTearDown(self):
        for server in self.servers:
            server.close()
            await server.wait_closed()

    async def server(self, port=0):
        async def accept(reader, writer):
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(accept, "127.0.0.1", port)
        self.servers.append(server)
        return server, server.sockets[0].getsockname()[1]

    async def test_actual_tcp_success_and_refusal(self):
        server, port = await self.server()
        probe = Probe("127.0.0.1", port)
        self.assertTrue((await tcp_probe(probe, 0.1)).ok)
        server.close()
        await server.wait_closed()
        self.assertFalse((await tcp_probe(probe, 0.1)).ok)

    async def test_quorum(self):
        server, port = await self.server()
        dead, dead_port = await self.server()
        dead.close()
        await dead.wait_closed()
        candidate = replace(configuration().routes[0].candidates[0],
                            probes=(Probe("127.0.0.1", port), Probe("127.0.0.1", dead_port)), quorum=1)
        self.assertTrue((await candidate_probe(candidate, 0.1)).ok)
        self.assertFalse((await candidate_probe(replace(candidate, quorum=2), 0.1)).ok)

    async def test_daemon_real_probe_failover_and_failback(self):
        primary, primary_port = await self.server()
        backup, backup_port = await self.server()
        config = configuration(interval=0.04, timeout=0.02, failures=2, successes=2,
                               failback_delay=0.16, stale_after=0.5)
        route = config.routes[0]
        route = replace(route, candidates=tuple(replace(c, probes=(Probe("127.0.0.1", port),))
                                               for c, port in zip(route.candidates, (primary_port, backup_port))))
        config = replace(config, routes=(route,), reconcile_interval=0.02, port=0)
        backend = DryRun()
        daemon = Daemon(config, backend)
        task = asyncio.create_task(daemon.run())

        async def until_selected(cid):
            async with asyncio.timeout(3):
                while (await backend.current(route)).paths != (cid,):
                    await asyncio.sleep(0.01)

        try:
            await until_selected("primary")
            primary.close()
            await primary.wait_closed()
            await until_selected("backup")
            await self.server(primary_port)
            await asyncio.sleep(0.08)
            self.assertEqual((await backend.current(route)).paths, ("backup",))
            await until_selected("primary")
            self.assertTrue(daemon.snapshot()["ready"])
            self.assertEqual([d.paths for _, d in backend.changes if d.action == "route"],
                             [("primary",), ("backup",), ("primary",)])
        finally:
            daemon.stop.set()
            await asyncio.wait_for(task, 3)

    async def test_http_status_ready_and_metrics(self):
        daemon = Daemon(configuration(), DryRun())
        server = await asyncio.start_server(daemon.http, "127.0.0.1", 0)
        self.servers.append(server)
        port = server.sockets[0].getsockname()[1]
        for path, code, fragment in (("/readyz", "503", '"ready": false'),
                                     ("/healthz", "200", '"live": true'),
                                     ("/metrics", "200", "route_discovery_ready 0"),
                                     ("/missing", "404", "not found")):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
            await writer.drain()
            response = (await reader.read()).decode()
            self.assertIn(f"HTTP/1.1 {code}", response)
            self.assertIn(fragment, response)
            writer.close()
            await writer.wait_closed()

    async def test_backend_failure_does_not_commit_desired_state(self):
        class Failing(DryRun):
            async def apply(self, route, decision):
                raise BackendError("cannot write")
        config = configuration(successes=1)
        daemon = Daemon(config, Failing())
        for state in daemon.policy.health.values():
            state.observe(True, time.monotonic(), config.health)
        with self.assertRaises(BackendError):
            await daemon.reconcile_once(config.routes[0])
        self.assertEqual(daemon.policy.installed[config.routes[0].prefix], ())

    async def test_frr_shutdown_withdraws_runtime_routes(self):
        config = replace(configuration("frr", successes=1, interval=0.04, timeout=0.02),
                         reconcile_interval=0.02, port=0)
        backend = DryRun()

        async def probe(candidate, timeout):
            return Result(True, 1)

        async def validate(config):
            pass

        daemon = Daemon(config, backend, apply=True, probe=probe, validate=validate)
        task = asyncio.create_task(daemon.run())
        try:
            async with asyncio.timeout(3):
                while not (await backend.current(config.routes[0])).paths:
                    await asyncio.sleep(0.01)
        finally:
            daemon.stop.set()
            await asyncio.wait_for(task, 3)
        self.assertEqual((await backend.current(config.routes[0])).action, "withdraw")

    async def test_bad_probe_pinning_never_marks_path_healthy(self):
        config = configuration(successes=1)

        async def bad_paths(config):
            raise BackendError("wrong probe table")

        async def should_not_probe(candidate, timeout):
            self.fail("probe ran with invalid path pinning")

        daemon = Daemon(config, DryRun(), apply=True, probe=should_not_probe, validate=bad_paths)
        route = config.routes[0]
        task = asyncio.create_task(daemon.probe_loop(route, route.candidates[0]))
        try:
            async with asyncio.timeout(1):
                while not daemon.probe_path_errors:
                    await asyncio.sleep(0.01)
        finally:
            daemon.stop.set()
            await task
        self.assertNotEqual(daemon.policy.health[route.prefix, "primary"].state, "up")
