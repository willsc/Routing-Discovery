import asyncio
import json
from pathlib import Path
import signal

from ..commands import BackendError
from ..config import ConfigError
from ..state import StateStore
from .config import load
from .daemon import RouteServer
from .frr import render
from .journal import Journal
from .propagation import Propagator


async def run(config, apply, withdraw=False):
    directory = config.state_dir if apply else str(Path(config.state_dir) / "dry-run")
    lock = StateStore(directory)
    lock.acquire()
    journal = None
    try:
        if withdraw and not (Path(directory) / "route-server.sqlite3").is_file():
            raise BackendError("withdraw requires the existing ownership journal; no routes will be adopted")
        journal = Journal(config, directory)
        if withdraw:
            propagator = Propagator(config, journal, apply=apply)
            # No peer ENI verification is needed to retire previously owned routes.
            async def no_targets():
                pass
            propagator.verify_targets = no_targets
            converged = await propagator.reconcile({})
            print(json.dumps(propagator.status, indent=2))
            if not converged:
                raise BackendError("withdrawal incomplete; inspect errors and retry with the same state directory")
            journal.save_fib({})
            return
        daemon = RouteServer(config, journal, apply)
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, daemon.stop.set)
        await daemon.run()
    finally:
        if journal:
            journal.close()
        lock.close()


def execute(args):
    if args.operation == "demo":
        from .demo import demo
        asyncio.run(demo())
        return 0
    if not args.config:
        raise ConfigError("server operation requires --config")
    config = load(args.config)
    if args.operation == "validate":
        print(f"Valid route server {config.id}: {len(config.endpoints)} endpoints, {len(config.peers)} peers, {len(config.propagations)} propagations")
    elif args.operation == "render-frr":
        if not args.endpoint:
            raise ConfigError("render-frr requires --endpoint")
        print(render(config, args.endpoint), end="")
    else:
        if args.operation == "withdraw" and not args.apply:
            raise ConfigError("server withdraw requires --apply and an existing ownership journal")
        asyncio.run(run(config, args.apply, args.operation == "withdraw"))
    return 0
