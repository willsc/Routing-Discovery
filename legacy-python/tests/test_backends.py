from dataclasses import replace
import json
import unittest

from route_discovery.backends import AWS, FRR, Linux, Observed, validate_probe_paths
from route_discovery.commands import BackendError
from route_discovery.policy import Decision
from .helpers import configuration


class LinuxTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.config = configuration()
        self.route = self.config.routes[0]
        self.records = []
        self.commands = []

        async def run(*args):
            self.commands.append(args)
            if "show" in args:
                return json.dumps(self.records)
            if "del" in args:
                self.records = []
            elif "unreachable" in args:
                self.records = [{"type": "unreachable", "protocol": 196, "metric": 100}]
            else:
                devices = [args[i + 1] for i, arg in enumerate(args) if arg == "dev"]
                self.records = [{"protocol": 196, "metric": 100, "nexthops": [{"dev": dev} for dev in devices]}]
            return ""

        self.backend = Linux(self.config, run)

    async def test_atomic_replace_and_withdraw(self):
        self.assertTrue(await self.backend.apply(self.route, Decision("route", ("primary",))))
        self.assertTrue(await self.backend.apply(self.route, Decision("route", ("backup",))))
        changes = [x for x in self.commands if "replace" in x]
        self.assertEqual(len(changes), 2)
        self.assertIn("wg-b", changes[1])
        self.assertTrue(await self.backend.apply(self.route, Decision("withdraw")))

    async def test_idempotent_and_unreachable(self):
        decision = Decision("route", ("primary",))
        await self.backend.apply(self.route, decision)
        await self.backend.apply(self.route, decision)
        self.assertEqual(sum("replace" in c for c in self.commands), 1)
        await self.backend.apply(self.route, Decision("unreachable"))
        self.assertEqual(await self.backend.current(self.route), Observed(action="unreachable"))

    async def test_refuses_foreign_routes(self):
        for record in ({"protocol": "static", "metric": 100, "dev": "wg-a"},
                       {"protocol": 196, "metric": 20, "dev": "wg-a"},
                       {"protocol": 196, "metric": 100, "dev": "eth9"}):
            self.records = [record]
            with self.assertRaises(BackendError):
                await self.backend.apply(self.route, Decision("withdraw"))

    async def test_ecmp_replace_contains_all_next_hops(self):
        self.assertTrue(await self.backend.apply(self.route, Decision("route", ("backup", "primary"))))
        command = next(c for c in self.commands if "replace" in c)
        self.assertEqual(command.count("nexthop"), 2)

    async def test_ipv6_route_family(self):
        route = replace(self.route, prefix="2001:db8::/64")
        await self.backend.apply(route, Decision("route", ("primary",)))
        self.assertTrue(all("-6" in c for c in self.commands))

    async def test_write_failure_is_propagated(self):
        async def fail(*args):
            if "show" in args:
                return "[]"
            raise BackendError("permission denied")
        with self.assertRaises(BackendError):
            await Linux(self.config, fail).apply(self.route, Decision("route", ("primary",)))

    async def test_probe_drift_is_rejected(self):
        async def wrong(*args):
            return json.dumps([{"table": 254, "dev": "wg-b"}])
        with self.assertRaises(BackendError):
            await validate_probe_paths(self.config, wrong)

    async def test_probe_correct_path_requires_terminal_route(self):
        async def right(*args):
            if "get" in args:
                return json.dumps([{"table": args[args.index("mark") + 1], "dev": args[args.index("oif") + 1]}])
            return json.dumps([{"type": "7"}])
        await validate_probe_paths(self.config, right)

    async def test_numeric_unreachable_route_type(self):
        self.records = [{"type": "7", "protocol": "196", "metric": 100}]
        self.assertEqual(await self.backend.current(self.route), Observed(action="unreachable"))


class FakeEC2:
    def __init__(self):
        self.routes = []
        self.tags = [{"Key": "route-discovery", "Value": "managed"}]
        self.calls = []
        self.fail = False
        self.lag = False

    def describe_route_tables(self, **kwargs):
        return {"RouteTables": [{"RouteTableId": "rtb-0123456789abcdef0", "Tags": self.tags, "Routes": self.routes.copy()}]}

    def create_route(self, **kwargs):
        self.calls.append(("create", kwargs))
        if self.fail:
            raise BackendError("Throttling")
        if not self.lag:
            self.routes = [{k: v for k, v in kwargs.items() if k != "RouteTableId"} | {"Origin": "CreateRoute", "State": "active"}]
        return {"Return": True}

    def replace_route(self, **kwargs):
        result = self.create_route(**kwargs)
        self.calls[-1] = ("replace", kwargs)
        return result

    def delete_route(self, **kwargs):
        self.calls.append(("delete", kwargs))
        self.routes = []
        return {}


class AWSTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.config = configuration("aws")
        self.route = self.config.routes[0]
        self.ec2 = FakeEC2()
        self.backend = AWS(self.config, self.ec2)

    async def test_create_failover_failback_delete(self):
        for cid in ("primary", "backup", "primary"):
            self.assertTrue(await self.backend.apply(self.route, Decision("route", (cid,))))
        self.assertTrue(await self.backend.apply(self.route, Decision("withdraw")))
        self.assertEqual([c[0] for c in self.ec2.calls], ["create", "replace", "replace", "delete"])

    async def test_no_write_on_same_target(self):
        decision = Decision("route", ("primary",))
        await self.backend.apply(self.route, decision)
        await self.backend.apply(self.route, decision)
        self.assertEqual(len(self.ec2.calls), 1)

    async def test_missing_ownership_tag_blocks_write(self):
        self.ec2.tags = []
        with self.assertRaises(BackendError):
            await self.backend.apply(self.route, Decision("route", ("primary",)))
        self.assertFalse(self.ec2.calls)

    async def test_foreign_local_and_propagated_routes_are_protected(self):
        for attrs in ({"GatewayId": "local", "Origin": "CreateRouteTable"},
                      {"NetworkInterfaceId": "eni-fffffffffffffffff", "Origin": "CreateRoute"},
                      {"NetworkInterfaceId": self.route.candidates[0].aws_target, "Origin": "EnableVgwRoutePropagation"}):
            self.ec2.routes = [{"DestinationCidrBlock": self.route.prefix, **attrs}]
            with self.assertRaises(BackendError):
                await self.backend.apply(self.route, Decision("withdraw"))

    async def test_eventual_consistency_not_reported_as_success(self):
        self.ec2.lag = True
        self.assertFalse(await self.backend.apply(self.route, Decision("route", ("primary",))))

    async def test_blackhole_not_treated_as_installed(self):
        await self.backend.apply(self.route, Decision("route", ("primary",)))
        self.ec2.routes[0]["State"] = "blackhole"
        self.assertFalse((await self.backend.current(self.route)).usable)
        self.assertTrue(await self.backend.apply(self.route, Decision("route", ("primary",))))
        self.assertEqual(self.ec2.calls[-1][0], "replace")

    async def test_ipv6_uses_correct_api_field(self):
        route = replace(self.route, prefix="2001:db8::/64")
        await self.backend.apply(route, Decision("route", ("primary",)))
        self.assertIn("DestinationIpv6CidrBlock", self.ec2.calls[-1][1])

    async def test_api_error_is_propagated(self):
        self.ec2.fail = True
        with self.assertRaises(BackendError):
            await self.backend.apply(self.route, Decision("route", ("primary",)))


class FRRTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.config = configuration("frr")
        self.route = self.config.routes[0]
        self.lines = set()
        self.changes = []

        async def run(*args):
            if "show running-config" in args:
                return "\n".join(sorted(self.lines))
            commands = [args[i + 1] for i, arg in enumerate(args) if arg == "-c"]
            self.changes.extend(commands)
            for command in commands:
                if command.startswith("ip route "):
                    self.lines.add(command)
                elif command.startswith("no ip route "):
                    self.lines.discard(command[3:])
            return ""

        self.backend = FRR(self.config, run)

    async def test_add_before_remove_and_withdraw(self):
        await self.backend.apply(self.route, Decision("route", ("primary",)))
        self.changes.clear()
        await self.backend.apply(self.route, Decision("route", ("backup",)))
        self.assertLess(self.changes.index(self.backend.command(self.route, self.route.candidates[1])),
                        self.changes.index("no " + self.backend.command(self.route, self.route.candidates[0])))
        await self.backend.apply(self.route, Decision("withdraw"))
        self.assertFalse(self.lines)

    async def test_restart_adopts_existing_tagged_routes(self):
        self.lines.add(self.backend.command(self.route, self.route.candidates[1]))
        self.assertEqual((await self.backend.current(self.route)).paths, ("backup",))

    async def test_other_static_route_blocks_modification(self):
        self.lines.add(f"ip route {self.route.prefix} eth9")
        with self.assertRaises(BackendError):
            await self.backend.apply(self.route, Decision("route", ("primary",)))
