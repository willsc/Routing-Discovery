"""Deterministic routing policy, independent of clocks, sockets and route writers."""

from dataclasses import dataclass
import math

from .config import Config, Health, Route


@dataclass
class PathHealth:
    state: str = "unknown"
    good: int = 0
    bad: int = 0
    last_sample: float | None = None
    up_since: float | None = None
    penalty: float = 0.0
    penalty_at: float | None = None
    suppressed_since: float | None = None
    last_error: str | None = None
    latency_ms: float | None = None

    def decay(self, now: float, h: Health):
        if self.penalty_at is not None:
            self.penalty *= math.exp2(-max(0.0, now - self.penalty_at) / h.dampening_half_life)
        self.penalty_at = now
        if self.suppressed_since is not None:
            if self.penalty < h.dampening_reuse or now - self.suppressed_since >= h.dampening_max:
                self.suppressed_since = None
                self.penalty = min(self.penalty, h.dampening_reuse)

    def down(self, now, h):
        if self.state == "up":
            self.penalty = min(self.penalty + h.dampening_penalty, h.dampening_suppress * 4)
            if self.penalty >= h.dampening_suppress and self.suppressed_since is None:
                self.suppressed_since = now
        self.state = "down"
        self.up_since = None

    def observe(self, success, now, h, error=None, latency_ms=None):
        self.decay(now, h)
        # A scheduler/probe gap breaks consecutive successes and invalidates an old UP.
        if self.last_sample is not None and now - self.last_sample >= h.stale_after:
            self.down(now, h)
            self.good = self.bad = 0
        self.last_sample = now
        self.last_error = error
        self.latency_ms = latency_ms
        if success:
            self.bad = 0
            self.good = min(self.good + 1, h.successes)
            if self.good >= h.successes and self.state != "up":
                self.state = "up"
                self.up_since = now
        else:
            self.good = 0
            self.bad = min(self.bad + 1, h.failures)
            if self.bad >= h.failures:
                self.down(now, h)

    def eligible(self, now, h):
        self.decay(now, h)
        if self.last_sample is not None and now - self.last_sample >= h.stale_after:
            self.down(now, h)
            self.good = 0
        return self.state == "up" and self.suppressed_since is None


@dataclass(frozen=True)
class Decision:
    action: str
    paths: tuple[str, ...] = ()
    reason: str = ""


class Policy:
    def __init__(self, config: Config, started=0.0):
        self.config = config
        self.started = started
        self.health = {(r.prefix, c.id): PathHealth() for r in config.routes for c in r.candidates}
        self.installed = {r.prefix: () for r in config.routes}

    def select(self, route: Route, now: float) -> Decision:
        h = self.config.health
        active = set(self.installed[route.prefix])
        eligible = []
        for c in route.candidates:
            state = self.health[route.prefix, c.id]
            healthy = state.eligible(now, h)
            if healthy and c.enabled and self.config.local_asn not in c.as_path:
                eligible.append(c)
        surviving = [c for c in eligible if c.id in active]
        if not eligible:
            pending = any(self.health[route.prefix, c.id].state == "unknown"
                          for c in route.candidates if c.enabled and self.config.local_asn not in c.as_path)
            if pending and now - self.started < h.stale_after:
                return Decision("hold", reason="initial health assessment")
            action = "hold" if route.all_down == "retain" else route.all_down
            return Decision(action, reason="no eligible path")
        if surviving:
            if not route.preempt:
                eligible = surviving
            else:
                # Hold-down only delays elective preemption, never emergency failover.
                eligible = [c for c in eligible if c.id in active or
                            now - self.health[route.prefix, c.id].up_since >= h.failback_delay]
        eligible.sort(key=lambda c: (c.rank, c.id not in active, c.id))
        best = eligible[0]
        equal = [c for c in eligible if c.rank == best.rank]
        paths = tuple(sorted(c.id for c in equal[:route.max_paths]))
        return Decision("route", paths, "best eligible policy rank")

    def commit(self, route, decision):
        if decision.action != "hold":
            self.installed[route.prefix] = decision.paths
