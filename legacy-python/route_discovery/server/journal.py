"""Durable route ownership and write intents, recorded before AWS mutation."""

from dataclasses import asdict
import json
from pathlib import Path
import sqlite3

from ..commands import BackendError
from .rib import LearnedRoute


class Journal:
    def __init__(self, config, directory=None):
        path = ":memory:" if directory is None else str(Path(directory) / "route-server.sqlite3")
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS routes (table_id TEXT, prefix TEXT, targets TEXT NOT NULL, PRIMARY KEY(table_id,prefix))")
        identity = {"server": config.id, "region": config.region, "vpc": config.vpc_id, "tag": config.owner_tag}
        row = self.db.execute("SELECT value FROM metadata WHERE key='identity'").fetchone()
        if row and json.loads(row[0]) != identity:
            self.db.close()
            raise BackendError("state directory belongs to a different route server, region, VPC or ownership tag")
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO metadata VALUES ('identity', ?)", (json.dumps(identity),))

    def entries(self):
        return {(table, prefix): set(json.loads(targets)) for table, prefix, targets in self.db.execute("SELECT table_id,prefix,targets FROM routes")}

    def intent(self, table, prefix, target):
        targets = self.entries().get((table, prefix), set()) | {target}
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO routes VALUES (?,?,?)", (table, prefix, json.dumps(sorted(targets))))

    def forget(self, table, prefix):
        with self.db:
            self.db.execute("DELETE FROM routes WHERE table_id=? AND prefix=?", (table, prefix))

    def save_fib(self, selected):
        value = json.dumps({p: asdict(r) for p, r in selected.items()})
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO metadata VALUES ('fib',?)", (value,))

    def load_fib(self, config):
        from .config import permits
        row = self.db.execute("SELECT value FROM metadata WHERE key='fib'").fetchone()
        result = {}
        peers = {p.id: p for p in config.peers}
        for prefix, data in (json.loads(row[0]) if row else {}).items():
            peer = peers.get(data["peer"])
            if peer and peer.eni == data["eni"] and data["next_hop"] in peer.next_hops and permits(prefix, peer.allowed_prefixes):
                data["as_path"] = tuple(data["as_path"])
                result[prefix] = LearnedRoute(**data)
        return result

    def close(self):
        self.db.close()
