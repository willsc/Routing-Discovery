import copy
import json
import sqlite3
from dataclasses import replace
import tempfile
import unittest

from route_discovery.commands import BackendError
from route_discovery.server.demo import demo_config
from route_discovery.server.frr import parse_snapshot
from route_discovery.server.journal import Journal
from route_discovery.server.propagation import Propagator
from .test_server import source_data


class EC2:
    def __init__(self, config):
        self.config = config
        self.tables = {p.table: {"RouteTableId": p.table, "VpcId": config.vpc_id,
                                "Tags": [{"Key": config.owner_tag, "Value": config.id}], "Routes": []}
                       for p in config.propagations}
        self.interfaces = [{"NetworkInterfaceId": p.eni, "VpcId": config.vpc_id,
                            "Status": "in-use", "SourceDestCheck": False,
                            "PrivateIpAddresses": [{"PrivateIpAddress": p.next_hops[0]}]} for p in config.peers]
        self.calls = []
        self.fail_table = None
        self.lag = False

    def describe_network_interfaces(self, **kwargs):
        return {"NetworkInterfaces": copy.deepcopy(self.interfaces)}

    def describe_route_tables(self, RouteTableIds):
        return {"RouteTables": [copy.deepcopy(self.tables[t]) for t in RouteTableIds]}

    def mutate(self, operation, **kwargs):
        self.calls.append((operation, kwargs))
        if kwargs["RouteTableId"] == self.fail_table:
            raise BackendError("AWS throttling")
        if not self.lag:
            table = self.tables[kwargs["RouteTableId"]]
            key = "DestinationCidrBlock" if "DestinationCidrBlock" in kwargs else "DestinationIpv6CidrBlock"
            table["Routes"] = [r for r in table["Routes"] if r.get(key) != kwargs[key]]
            if operation != "delete":
                table["Routes"].append({key: kwargs[key], "NetworkInterfaceId": kwargs["NetworkInterfaceId"], "Origin": "CreateRoute", "State": "active"})
        return {"Return": True}

    def create_route(self, **kwargs):
        return self.mutate("create", **kwargs)

    def replace_route(self, **kwargs):
        return self.mutate("replace", **kwargs)

    def delete_route(self, **kwargs):
        return self.mutate("delete", **kwargs)


class PropagationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.config = demo_config()
        self.journal = Journal(self.config)
        self.ec2 = EC2(self.config)
        self.backend = Propagator(self.config, self.journal, self.ec2, apply=True)
        self.a, self.b = parse_snapshot(self.config, self.config.endpoints[0], source_data()).routes

    async def asyncTearDown(self):
        self.journal.close()

    async def test_multi_table_learning_failover_and_withdrawal(self):
        for route in (self.a, self.b, self.a):
            self.assertTrue(await self.backend.reconcile({route.prefix: route}))
        self.assertTrue(await self.backend.reconcile({}))
        self.assertEqual([c[0] for c in self.ec2.calls].count("create"), 2)
        self.assertEqual([c[0] for c in self.ec2.calls].count("replace"), 4)
        self.assertEqual([c[0] for c in self.ec2.calls].count("delete"), 2)
        self.assertFalse(self.journal.entries())

    async def test_does_not_adopt_unowned_route_even_with_same_target(self):
        table = self.config.propagations[0].table
        self.ec2.create_route(RouteTableId=table, DestinationCidrBlock=self.a.prefix, NetworkInterfaceId=self.a.eni)
        self.ec2.calls.clear()
        self.assertFalse(await self.backend.reconcile({self.a.prefix: self.a}))
        self.assertNotIn((table, self.a.prefix), self.journal.entries())
        self.assertTrue(self.backend.status[self.config.propagations[1].table]["converged"])

    async def test_intent_is_durable_before_api_write(self):
        with tempfile.TemporaryDirectory() as directory:
            self.journal.close()
            self.journal = Journal(self.config, directory)
            self.backend.journal = self.journal
            original = self.ec2.create_route
            def check(**kwargs):
                key = (kwargs["RouteTableId"], kwargs["DestinationCidrBlock"])
                with sqlite3.connect(directory + "/route-server.sqlite3") as reader:
                    targets = reader.execute("SELECT targets FROM routes WHERE table_id=? AND prefix=?", key).fetchone()[0]
                self.assertIn(kwargs["NetworkInterfaceId"], json.loads(targets))
                return original(**kwargs)
            self.ec2.create_route = check
            self.assertTrue(await self.backend.reconcile({self.a.prefix: self.a}))

    async def test_partial_failure_does_not_block_other_table(self):
        self.ec2.fail_table = self.config.propagations[0].table
        self.assertFalse(await self.backend.reconcile({self.a.prefix: self.a}))
        self.assertTrue(self.backend.status[self.config.propagations[1].table]["converged"])
        self.ec2.fail_table = None
        self.assertTrue(await self.backend.reconcile({self.a.prefix: self.a}))

    async def test_eventual_consistency_and_delayed_deletion(self):
        self.ec2.lag = True
        self.assertFalse(await self.backend.reconcile({self.a.prefix: self.a}))
        self.ec2.lag = False
        self.assertTrue(await self.backend.reconcile({self.a.prefix: self.a}))
        self.ec2.lag = True
        self.assertFalse(await self.backend.reconcile({}))
        self.assertTrue(self.journal.entries())
        self.ec2.lag = False
        self.assertTrue(await self.backend.reconcile({}))
        self.assertFalse(self.journal.entries())

    async def test_missing_tag_wrong_vpc_and_local_route_are_protected(self):
        table = self.config.propagations[0].table
        self.ec2.tables[table]["Tags"] = []
        self.assertFalse(await self.backend.reconcile({self.a.prefix: self.a}))
        self.assertIn("ownership tag", self.backend.status[table]["error"])
        self.ec2.tables[table]["Tags"] = [{"Key": self.config.owner_tag, "Value": self.config.id}]
        self.ec2.tables[table]["VpcId"] = "vpc-fffffffffffffffff"
        self.assertFalse(await self.backend.reconcile({self.a.prefix: self.a}))
        self.ec2.tables[table]["VpcId"] = self.config.vpc_id
        self.ec2.tables[table]["Routes"] = [{"DestinationCidrBlock": self.a.prefix, "Origin": "CreateRouteTable", "GatewayId": "local"}]
        self.assertFalse(await self.backend.reconcile({self.a.prefix: self.a}))
        self.assertIn("journal-owned", self.backend.status[table]["routes"][self.a.prefix]["error"])

    async def test_eni_mapping_and_source_destination_checks(self):
        self.ec2.interfaces[0]["SourceDestCheck"] = True
        with self.assertRaises(BackendError):
            await self.backend.reconcile({self.a.prefix: self.a})
        self.ec2.interfaces[0]["SourceDestCheck"] = False
        self.ec2.interfaces[0]["PrivateIpAddresses"] = []
        with self.assertRaises(BackendError):
            await self.backend.reconcile({self.a.prefix: self.a})

    async def test_removed_or_disabled_propagation_cleans_owned_routes(self):
        await self.backend.reconcile({self.a.prefix: self.a})
        self.backend.config = replace(self.config, propagations=(self.config.propagations[1],))
        self.assertTrue(await self.backend.reconcile({self.a.prefix: self.a}))
        self.assertFalse(self.ec2.tables[self.config.propagations[0].table]["Routes"])
        self.backend.config = replace(self.config, propagations=tuple(replace(p, enabled=False) for p in self.config.propagations))
        self.assertTrue(await self.backend.reconcile({self.a.prefix: self.a}))
        self.assertFalse(self.journal.entries())

    async def test_prefix_filter_and_ipv6_api_field(self):
        self.backend.config = replace(self.config, propagations=(replace(self.config.propagations[0], allowed_prefixes=("2001:db8::/32",)),))
        route6 = replace(self.a, prefix="2001:db8:20::/64")
        self.assertTrue(await self.backend.reconcile({self.a.prefix: self.a, route6.prefix: route6}))
        self.assertEqual(len(self.ec2.calls), 1)
        self.assertIn("DestinationIpv6CidrBlock", self.ec2.calls[0][1])

    async def test_generation_guard_prevents_obsolete_writes(self):
        self.assertFalse(await self.backend.reconcile({self.a.prefix: self.a}, guard=lambda: False))
        self.assertFalse(self.ec2.calls)

    async def test_unexpected_target_after_restart_is_not_overwritten(self):
        await self.backend.reconcile({self.a.prefix: self.a})
        for table in self.ec2.tables.values():
            table["Routes"][0]["NetworkInterfaceId"] = "eni-fffffffffffffffff"
        self.assertFalse(await self.backend.reconcile({self.b.prefix: self.b}))
        self.assertFalse(await self.backend.reconcile({}))

    async def test_dry_run_never_reads_aws(self):
        backend = Propagator(self.config, self.journal, client=object(), apply=False)
        self.assertTrue(await backend.reconcile({self.a.prefix: self.a}))
        self.assertEqual(len(backend.simulated), 2)

    async def test_maximum_route_count_holds_table(self):
        self.backend.config = replace(self.config, propagations=tuple(replace(p, max_routes=1) for p in self.config.propagations))
        extra = replace(self.a, prefix="10.20.2.0/24")
        self.assertFalse(await self.backend.reconcile({self.a.prefix: self.a, extra.prefix: extra}))
        self.assertFalse(self.ec2.calls)
