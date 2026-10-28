"""Learned routes, endpoint expiry, deterministic selection and recovery hold-down."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class LearnedRoute:
    prefix: str
    peer: str
    endpoint: str
    eni: str
    next_hop: str
    as_path: tuple[int, ...]
    med: int
    local_pref: int

    @property
    def key(self):
        return (self.prefix, self.peer, self.next_hop)

    @property
    def rank(self):
        return (-self.local_pref, len(self.as_path), self.med)


@dataclass(frozen=True)
class Snapshot:
    routes: tuple[LearnedRoute, ...]
    peers: dict
    rejected: tuple[dict, ...] = ()


class RIB:
    def __init__(self, config):
        self.config = config
        self.snapshots = {}
        self.since = {}
        self.selected = {}
        self.persisted = False
        self.resume_at = None
        self.started = None

    def update(self, endpoint, snapshot, now):
        old = self.snapshots.get(endpoint)
        fresh_old = old is not None and now - old[0] < self.config.stale_after
        old_keys = {r.key for r in old[1].routes} if fresh_old else set()
        new_keys = {r.key for r in snapshot.routes}
        for key in old_keys - new_keys:
            self.since.pop(key, None)
        for key in new_keys:
            if key not in old_keys:
                self.since[key] = now
        self.snapshots[endpoint] = (now, snapshot)

    def fresh(self, now):
        result = {}
        for eid, (at, snapshot) in self.snapshots.items():
            if now - at < self.config.stale_after:
                result[eid] = snapshot
            else:
                for route in snapshot.routes:
                    self.since.pop(route.key, None)
        return result

    def select(self, now):
        snapshots = self.fresh(now)
        any_up = any(p["up"] for s in snapshots.values() for p in s.peers.values())
        if self.config.persist_routes:
            if not any_up:
                self.persisted = bool(self.selected)
                self.resume_at = None
                return self.selected.copy()
            if self.persisted:
                if self.resume_at is None:
                    self.resume_at = now + self.config.persist_duration
                if now < self.resume_at:
                    return self.selected.copy()
                self.persisted = False
                self.resume_at = None
        choices = {}
        for snapshot in snapshots.values():
            for route in snapshot.routes:
                choices.setdefault(route.prefix, []).append(route)
        selected = {}
        for prefix, candidates in choices.items():
            current = self.selected.get(prefix)
            surviving = next((r for r in candidates if current and r.key == current.key), None)
            if surviving:
                candidates = [r for r in candidates if r.key == surviving.key or
                              now - self.since.get(r.key, now) >= self.config.failback_delay]
            candidates.sort(key=lambda r: (r.rank, r.key != (current.key if current else None), r.peer, r.next_hop))
            selected[prefix] = candidates[0]
        self.selected = selected
        return selected.copy()

    def view(self, now):
        fresh = self.fresh(now)
        return {
            "persisted": self.persisted,
            "resume_in": None if self.resume_at is None else max(0, self.resume_at - now),
            "endpoints": {e.id: {"fresh": e.id in fresh,
                                  "age": None if e.id not in self.snapshots else now - self.snapshots[e.id][0]}
                          for e in self.config.endpoints},
            "peers": {p.id: fresh[p.endpoint].peers.get(p.id, {"up": False, "reason": "missing peer"})
                      if p.endpoint in fresh else {"up": False, "reason": "endpoint data expired"}
                      for p in self.config.peers},
            "rib": [asdict(r) for s in fresh.values() for r in s.routes],
            "fib": {prefix: asdict(route) for prefix, route in self.selected.items()},
            "rejected": [r for s in fresh.values() for r in s.rejected],
        }
