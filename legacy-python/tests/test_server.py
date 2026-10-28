import copy
from dataclasses import replace
from pathlib import Path
import tempfile
import tomllib
import unittest

from route_discovery.commands import BackendError
from route_discovery.config import ConfigError
from route_discovery.server.config import load, parse
from route_discovery.server.demo import demo_config
from route_discovery.server.frr import parse_snapshot, render
from route_discovery.server.journal import Journal
from route_discovery.server.rib import LearnedRoute, RIB, Snapshot


ROOT = Path(__file__).resolve().parents[1]


def source_data(config=None):
    config = config or demo_config()
    return {
        "summary": {"ipv4Unicast": {"peers": {p.address: {"state": "Established", "remoteAs": p.asn} for p in config.peers}}},
        "bfd": [{"peer": p.address, "local": config.endpoints[0].address, "status": "up"} for p in config.peers],
        "ipv4": {"routes": {"10.20.1.0/24": [
            {"peerId": p.address, "valid": True, "path": str(p.asn), "metric": med,
             "nexthops": [{"ip": p.next_hops[0]}]} for p, med in zip(config.peers, (10, 100))]}},
    }


class ServerConfigTests(unittest.TestCase):
    def setUp(self):
        self.raw = tomllib.loads((ROOT / "examples/route-server.toml").read_text())

    def test_example_and_endpoint_config(self):
        config = parse(self.raw)
        text = render(config, "endpoint-a")
        self.assertIn("bgp no-rib", text)
        self.assertIn("maximum-prefix 100", text)
        self.assertIn("RDS-DENY-OUT out", text)
        self.assertIn("neighbor 10.0.1.10 bfd", text)
        self.assertNotIn("neighbor 10.0.2.10", text)

    def test_typo_duplicate_endpoint_and_unknown_peer_endpoint(self):
        for modify in (
            lambda raw: raw["server"].update(poll_intervl=1),
            lambda raw: raw["endpoints"].append(raw["endpoints"][0]),
            lambda raw: raw["peers"][0].update(endpoint="missing"),
            lambda raw: raw["peers"][0].update(asn=raw["server"]["asn"]),
            lambda raw: raw["propagations"][0].update(enabled="yes"),
        ):
            raw = copy.deepcopy(self.raw)
            modify(raw)
            with self.assertRaises(ConfigError):
                parse(raw)


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.config = demo_config()
        self.endpoint = self.config.endpoints[0]
        self.raw = source_data(self.config)

    def snapshot(self):
        return parse_snapshot(self.config, self.endpoint, self.raw)

    def test_learns_all_paths_not_just_frr_best(self):
        snapshot = self.snapshot()
        self.assertEqual(len(snapshot.routes), 2)
        self.assertEqual(snapshot.routes[0].med, 10)
        self.assertEqual(snapshot.routes[1].as_path, (65020,))

    def test_bfd_down_withdraws_only_failed_peer(self):
        self.raw["bfd"][0]["status"] = "down"
        result = self.snapshot()
        self.assertEqual([r.peer for r in result.routes], ["backup"])
        self.assertFalse(result.peers["primary"]["up"])

    def test_wrong_asn_or_bgp_down_excludes_peer(self):
        self.raw["summary"]["ipv4Unicast"]["peers"]["10.0.1.10"]["remoteAs"] = 123
        self.assertEqual(len(self.snapshot().routes), 1)
        self.raw["summary"]["ipv4Unicast"]["peers"]["10.0.1.20"]["state"] = "Active"
        self.assertFalse(self.snapshot().routes)

    def test_stale_path_loop_bad_next_hop_and_as_set_are_rejected(self):
        original = self.raw["ipv4"]["routes"]["10.20.1.0/24"][0]
        for update in ({"stale": True}, {"valid": False}, {"path": "65010 64512"},
                       {"path": "65010 {65100,65200}"}, {"nexthops": [{"ip": "10.99.99.99"}]}, {"metric": -1}):
            self.raw["ipv4"]["routes"]["10.20.1.0/24"][0] = original | update
            result = self.snapshot()
            self.assertEqual(len(result.routes), 1)
            self.assertEqual(len(result.rejected), 1)

    def test_prefix_filter_and_maximum_prefix(self):
        self.raw["ipv4"]["routes"]["0.0.0.0/0"] = self.raw["ipv4"]["routes"]["10.20.1.0/24"]
        self.assertEqual(len(self.snapshot().routes), 2)
        self.config = replace(self.config, peers=tuple(replace(p, max_prefixes=1) for p in self.config.peers))
        self.assertFalse(self.snapshot().routes)

    def test_malformed_snapshot_is_not_a_withdrawal(self):
        for data in ({}, {"summary": {}}, self.raw | {"ipv4": {"warning": "BGP unavailable"}},
                     self.raw | {"bfd": {}}, self.raw | {"ipv4": {"routes": []}}):
            with self.assertRaises(BackendError):
                parse_snapshot(self.config, self.endpoint, data)

    def test_ipv6_nlri(self):
        peers = tuple(replace(p, allowed_prefixes=("2001:db8:20::/48",), next_hops=(f"2001:db8::{i}",))
                      for i, p in enumerate(self.config.peers, 1))
        config = replace(self.config, peers=peers)
        raw = source_data(config)
        raw["summary"]["ipv6Unicast"] = raw["summary"].pop("ipv4Unicast")
        raw["ipv6"] = {"routes": {"2001:db8:20:1::/64": raw.pop("ipv4")["routes"]["10.20.1.0/24"]}}
        self.assertEqual(len(parse_snapshot(config, self.endpoint, raw).routes), 2)


class RIBTests(unittest.TestCase):
    def setUp(self):
        self.config = demo_config()
        self.rib = RIB(self.config)
        self.snapshot = parse_snapshot(self.config, self.config.endpoints[0], source_data())

    def test_failover_failback_and_withdrawal(self):
        self.rib.update("edge", self.snapshot, 0)
        self.assertEqual(self.rib.select(0)["10.20.1.0/24"].peer, "primary")
        backup = replace(self.snapshot, routes=self.snapshot.routes[1:])
        self.rib.update("edge", backup, 1)
        self.assertEqual(self.rib.select(1)["10.20.1.0/24"].peer, "backup")
        self.rib.update("edge", self.snapshot, 2)
        self.assertEqual(self.rib.select(2)["10.20.1.0/24"].peer, "backup")
        self.assertEqual(self.rib.select(7)["10.20.1.0/24"].peer, "primary")
        self.rib.update("edge", replace(self.snapshot, routes=()), 8)
        self.assertFalse(self.rib.select(8))

    def test_stale_source_expires_and_recovery_restarts_hold_down(self):
        self.rib.update("edge", self.snapshot, 0)
        self.rib.select(0)
        self.assertFalse(self.rib.select(11))
        self.rib.update("edge", self.snapshot, 12)
        self.assertEqual(self.rib.since[self.snapshot.routes[0].key], 12)

    def test_rank_prefers_aspath_before_med(self):
        a, b = self.snapshot.routes
        self.rib.update("edge", replace(self.snapshot, routes=(replace(a, as_path=(65010, 65100)), b)), 0)
        self.assertEqual(self.rib.select(0)[a.prefix].peer, "backup")

    def test_persistence_when_all_peers_down_and_resume_delay(self):
        self.rib = RIB(replace(self.config, persist_routes=True, persist_duration=60))
        self.rib.update("edge", self.snapshot, 0)
        original = self.rib.select(0)
        down = Snapshot((), {p.id: {"up": False} for p in self.config.peers})
        self.rib.update("edge", down, 1)
        self.assertEqual(self.rib.select(1), original)
        self.assertTrue(self.rib.persisted)
        self.rib.update("edge", replace(self.snapshot, routes=self.snapshot.routes[1:]), 2)
        self.assertEqual(self.rib.select(2), original)
        for tick in (10, 18, 26, 34, 42, 50, 58, 62):
            self.rib.update("edge", replace(self.snapshot, routes=self.snapshot.routes[1:]), tick)
            selected = self.rib.select(tick)
        self.assertEqual(selected["10.20.1.0/24"].peer, "backup")
        self.assertFalse(self.rib.persisted)

    def test_one_remaining_peer_allows_normal_withdrawal_with_persistence(self):
        self.rib = RIB(replace(self.config, persist_routes=True))
        self.rib.update("edge", self.snapshot, 0)
        self.rib.select(0)
        self.rib.update("edge", Snapshot((), {"backup": {"up": True}}), 1)
        self.assertFalse(self.rib.select(1))


class JournalTests(unittest.TestCase):
    def test_restart_recovers_intents_and_fib_and_rejects_wrong_identity(self):
        config = demo_config()
        with tempfile.TemporaryDirectory() as directory:
            journal = Journal(config, directory)
            journal.intent(config.propagations[0].table, "10.20.1.0/24", config.peers[0].eni)
            route = parse_snapshot(config, config.endpoints[0], source_data()).routes[0]
            journal.save_fib({route.prefix: route})
            journal.close()
            journal = Journal(config, directory)
            self.assertEqual(journal.load_fib(config)[route.prefix], route)
            self.assertEqual(len(journal.entries()), 1)
            journal.close()
            with self.assertRaises(BackendError):
                Journal(replace(config, id="other"), directory)
