import copy
from pathlib import Path
import tomllib
import unittest

from route_discovery.config import ConfigError, load, parse
from route_discovery.backends import probe_plan
from route_discovery.cli import frr_config


ROOT = Path(__file__).resolve().parents[1]


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.raw = tomllib.loads((ROOT / "examples/linux.toml").read_text())

    def test_all_examples_validate(self):
        for path in (ROOT / "examples").glob("*.toml"):
            if path.name == "route-server.toml":
                continue
            self.assertTrue(load(path).routes)

    def test_unknown_key_and_duplicate_prefix_rejected(self):
        self.raw["health"]["sucesses"] = 3
        with self.assertRaises(ConfigError):
            parse(self.raw)
        del self.raw["health"]["sucesses"]
        self.raw["routes"].append(copy.deepcopy(self.raw["routes"][0]))
        with self.assertRaises(ConfigError):
            parse(self.raw)

    def test_unpinned_probes_rejected(self):
        del self.raw["routes"][0]["candidates"][0]["probes"][0]["mark"]
        with self.assertRaises(ConfigError):
            parse(self.raw)

    def test_shared_probe_mark_rejected(self):
        self.raw["routes"][0]["candidates"][1]["probes"][0]["mark"] = 10101
        with self.assertRaises(ConfigError):
            parse(self.raw)

    def test_strict_types_and_ranges(self):
        for key, value in (("interval", float("nan")), ("failures", True), ("timeout", 5), ("stale_after", 0)):
            raw = copy.deepcopy(self.raw)
            raw["health"][key] = value
            with self.subTest(key=key), self.assertRaises(ConfigError):
                parse(raw)

    def test_injection_in_device_rejected(self):
        self.raw["routes"][0]["candidates"][0]["device"] = "wg0;reboot"
        with self.assertRaises(ConfigError):
            parse(self.raw)

    def test_aws_rejects_ecmp_and_missing_path_contract(self):
        raw = tomllib.loads((ROOT / "examples/aws.toml").read_text())
        raw["routes"][0]["max_paths"] = 2
        with self.assertRaises(ConfigError):
            parse(raw)
        raw["routes"][0]["max_paths"] = 1
        del raw["routes"][0]["candidates"][0]["probes"][0]["external_path"]
        with self.assertRaises(ConfigError):
            parse(raw)

    def test_bgp_protocol_cannot_be_claimed(self):
        self.raw["backend"]["protocol"] = 186
        with self.assertRaises(ConfigError):
            parse(self.raw)

    def test_plan_has_terminal_route_and_two_isolated_tables(self):
        script = probe_plan(parse(self.raw))
        self.assertIn("unreachable default table 10101", script)
        self.assertIn("unreachable default table 10102", script)
        self.assertIn("fwmark 10101/0xffffffff lookup 10101", script)
        self.assertNotIn("flush", script)

    def test_frr_export_has_prefix_and_tag_filter(self):
        config = load(ROOT / "examples/frr.toml")
        text = frr_config(config, "10.0.1.10", "10.0.1.20", 64512, 100)
        self.assertIn("match tag 42420", text)
        self.assertIn("permit 10.20.0.0/16", text)
        self.assertIn("neighbor 10.0.1.20 bfd", text)
        self.assertIn("route-map RD-IN deny 10", text)
        self.assertIn("redistribute static route-map RD-STATIC4", text)
