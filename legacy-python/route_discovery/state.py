"""A process lock and atomic dampening checkpoint; health is always re-probed."""

import fcntl
import json
import math
import os
from pathlib import Path
import time

from .commands import BackendError


class StateStore:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.lock = None

    def acquire(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = (self.directory / "daemon.lock").open("a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.close()
            raise BackendError("another daemon holds this state directory lock") from exc

    def close(self):
        if self.lock:
            self.lock.close()
            self.lock = None

    def save(self, policy, now):
        data = {"version": 1, "saved_at": time.time(), "paths": {}}
        for (prefix, cid), state in policy.health.items():
            state.decay(now, policy.config.health)
            data["paths"][f"{prefix}|{cid}"] = {
                "penalty": state.penalty,
                "suppressed_age": None if state.suppressed_since is None else now - state.suppressed_since,
            }
        temporary = self.directory / "dampening.json.tmp"
        with temporary.open("w") as stream:
            json.dump(data, stream, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.directory / "dampening.json")

    def restore(self, policy, now):
        path = self.directory / "dampening.json"
        if not path.exists():
            return
        data = json.loads(path.read_text())
        if data.get("version") != 1:
            raise BackendError("unsupported dampening checkpoint version")
        elapsed = max(0.0, time.time() - float(data["saved_at"]))
        if not math.isfinite(elapsed):
            raise BackendError("invalid checkpoint timestamp")
        h = policy.config.health
        for (prefix, cid), state in policy.health.items():
            saved = data["paths"].get(f"{prefix}|{cid}")
            if saved is None:
                continue
            penalty = float(saved["penalty"])
            age = saved["suppressed_age"]
            if not math.isfinite(penalty) or penalty < 0 or (age is not None and (not math.isfinite(age) or age < 0)):
                raise BackendError("invalid dampening checkpoint")
            state.penalty = min(penalty, h.dampening_suppress * 4) * math.exp2(-elapsed / h.dampening_half_life)
            state.penalty_at = now
            if age is not None:
                state.suppressed_since = now - age - elapsed
            state.decay(now, h)
