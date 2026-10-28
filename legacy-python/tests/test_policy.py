from dataclasses import replace
import unittest

from route_discovery.policy import Policy
from .helpers import configuration


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.config = configuration(failures=3, successes=2, failback_delay=5)
        self.route = self.config.routes[0]
        self.policy = Policy(self.config)

    def sample(self, tick, primary=True, backup=True, commit=True):
        for cid, ok in (("primary", primary), ("backup", backup)):
            self.policy.health[self.route.prefix, cid].observe(ok, tick, self.config.health)
        decision = self.policy.select(self.route, tick)
        if commit:
            self.policy.commit(self.route, decision)
        return decision

    def test_failover_and_delayed_failback(self):
        self.assertEqual(self.sample(0).action, "hold")
        self.assertEqual(self.sample(1).paths, ("primary",))
        self.assertEqual(self.sample(2, False).paths, ("primary",))
        self.assertEqual(self.sample(3, False).paths, ("primary",))
        self.assertEqual(self.sample(4, False).paths, ("backup",))
        for tick in range(5, 11):
            self.assertEqual(self.sample(tick).paths, ("backup",))
        self.assertEqual(self.sample(11).paths, ("primary",))

    def test_emergency_ignores_preemption_hold(self):
        self.sample(0, False)
        self.sample(1, False)
        self.sample(2, True, False)
        self.sample(3, True, False)
        self.assertEqual(self.sample(4, True, False).paths, ("primary",))

    def test_all_down_and_recovery(self):
        self.sample(0)
        self.sample(1)
        for tick in range(2, 4):
            self.sample(tick, False, False)
        self.assertEqual(self.sample(4, False, False).action, "withdraw")
        self.sample(5)
        self.assertEqual(self.sample(6).paths, ("primary",))

    def test_all_down_modes_and_startup_grace(self):
        self.assertEqual(self.policy.select(self.route, 1).action, "hold")
        self.assertEqual(self.policy.select(self.route, 6).action, "withdraw")
        self.assertEqual(self.policy.select(replace(self.route, all_down="retain"), 6).action, "hold")
        self.assertEqual(self.policy.select(replace(self.route, all_down="unreachable"), 6).action, "unreachable")

    def test_stale_health_cannot_keep_route(self):
        self.sample(0)
        self.sample(1)
        self.assertEqual(self.policy.select(self.route, 7).action, "withdraw")
        self.assertEqual(self.sample(8).action, "withdraw")
        self.assertEqual(self.sample(9).paths, ("primary",))

    def test_nonpreemptive_route_stays_on_backup(self):
        self.route = replace(self.route, preempt=False)
        self.sample(0, False)
        self.sample(1, False)
        for tick in range(2, 20):
            self.assertEqual(self.sample(tick).paths, ("backup",))

    def test_as_loop_and_disabled_paths_are_excluded(self):
        primary, backup = self.route.candidates
        self.route = replace(self.route, candidates=(replace(primary, as_path=(65000,)), backup))
        self.sample(0)
        self.assertEqual(self.sample(1).paths, ("backup",))
        self.route = replace(self.route, candidates=(replace(primary, enabled=False), backup))
        self.assertEqual(self.sample(2).paths, ("backup",))

    def test_ecmp_and_failed_member_removal(self):
        primary, backup = self.route.candidates
        self.route = replace(self.route, max_paths=2, candidates=(primary, replace(backup, local_pref=200)))
        self.sample(0)
        self.assertEqual(self.sample(1).paths, ("backup", "primary"))
        for tick in range(2, 4):
            self.sample(tick, False)
        self.assertEqual(self.sample(4, False).paths, ("backup",))

    def test_rank_localpref_aspath_med_cost(self):
        primary, backup = self.route.candidates
        for attrs in ({"local_pref": 201}, {"local_pref": 200, "as_path": ()},
                      {"local_pref": 200, "as_path": (1,), "med": 1},
                      {"local_pref": 200, "as_path": (1,), "med": 2, "cost": 1}):
            a = replace(primary, as_path=(1,), med=2, cost=2)
            b = replace(backup, **attrs)
            self.assertLess(b.rank, a.rank)

    def test_dampening_decays_and_is_bounded(self):
        h = replace(self.config.health, failures=1, successes=1, dampening_suppress=1500,
                    dampening_half_life=100, dampening_max=10)
        state = self.policy.health[self.route.prefix, "primary"]
        state.observe(True, 0, h)
        state.observe(False, 1, h)
        state.observe(True, 2, h)
        state.observe(False, 3, h)
        state.observe(True, 4, h)
        self.assertFalse(state.eligible(4, h))
        for tick in range(5, 14):
            state.observe(True, tick, h)
        self.assertTrue(state.eligible(13, h))

    def test_uncommitted_decision_does_not_change_installed(self):
        self.sample(0)
        self.assertEqual(self.sample(1, commit=False).paths, ("primary",))
        self.assertEqual(self.policy.installed[self.route.prefix], ())
