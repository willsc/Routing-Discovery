import argparse
import asyncio
import ipaddress
import json
import logging
from pathlib import Path
import signal
import sys
from urllib.request import urlopen

from .backends import make_backend, probe_plan, validate_probe_paths
from .commands import BackendError
from .config import ConfigError, load
from .daemon import Daemon
from .state import StateStore
from .policy import Decision


def frr_config(config, router_id, peer, peer_asn, med):
    router_id = str(ipaddress.IPv4Address(router_id))
    peer = str(ipaddress.ip_address(peer))
    if not 1 <= peer_asn <= 2**32 - 1 or not 0 <= med <= 2**32 - 1:
        raise ConfigError("invalid peer ASN or MED")
    if config.backend.kind != "frr":
        raise ConfigError("render-frr requires backend.kind=frr")
    lines = ["! Merge this fragment into FRR; enable zebra, staticd, bgpd and bfdd.",
             "! Reserve RD-* policy names and this route tag exclusively for route-discovery.",
             "! No health-dependent static routes should be saved to frr.conf.",
             "route-map RD-IN deny 10", "!"]
    families = sorted({ipaddress.ip_network(r.prefix).version for r in config.routes})
    for version in families:
        cmd = "ip" if version == 4 else "ipv6"
        for i, route in enumerate(r for r in config.routes if ipaddress.ip_network(r.prefix).version == version):
            lines.append(f"{cmd} prefix-list RD-V{version} seq {(i + 1) * 10} permit {route.prefix}")
        lines += [f"route-map RD-STATIC{version} permit 10", f" match tag {config.backend.frr_tag}",
                  f" match {cmd} address prefix-list RD-V{version}", f" set metric {med}", "!",
                  f"route-map RD-OUT{version} permit 10", f" match {cmd} address prefix-list RD-V{version}", "!"]
    lines += [f"router bgp {config.local_asn}", f" bgp router-id {router_id}", " no bgp default ipv4-unicast",
              f" neighbor {peer} remote-as {peer_asn}", f" neighbor {peer} bfd"]
    for version in families:
        lines += [f" address-family ipv{version} unicast", f"  neighbor {peer} activate",
                  f"  neighbor {peer} route-map RD-IN in", f"  neighbor {peer} route-map RD-OUT{version} out",
                  f"  redistribute static route-map RD-STATIC{version}", " exit-address-family"]
    return "\n".join(lines) + "\n"


async def run_daemon(config, apply):
    # Dry runs have a separate lock/checkpoint; they cannot reset live dampening state.
    directory = config.state_dir if apply else str(Path(config.state_dir) / "dry-run")
    store = StateStore(directory)
    store.acquire()
    try:
        daemon = Daemon(config, make_backend(config, apply), store, apply)
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, daemon.stop.set)
        await daemon.run()
    finally:
        store.close()


async def cleanup(config):
    """systemd ExecStopPost also runs after SIGKILL/watchdog failures."""
    if config.backend.kind != "frr":
        return
    store = StateStore(config.state_dir)
    store.acquire()
    try:
        backend = make_backend(config, True)
        for route in config.routes:
            if not await backend.apply(route, Decision("withdraw", reason="supervisor cleanup")):
                raise BackendError(f"FRR withdrawal did not converge: {route.prefix}")
    finally:
        store.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Health-driven Linux/AWS routing, with FRR BGP integration")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "probe-plan", "check-paths", "run", "render-frr", "cleanup-frr"):
        sub = commands.add_parser(command)
        sub.add_argument("--config", "-c", required=True)
        if command in ("run", "cleanup-frr"):
            sub.add_argument("--apply", action="store_true", help="write live routes (default is in-memory dry-run)")
        if command == "render-frr":
            sub.add_argument("--router-id", required=True)
            sub.add_argument("--peer", required=True)
            sub.add_argument("--peer-asn", type=int, required=True)
            sub.add_argument("--med", type=int, default=100)
    status = commands.add_parser("status")
    status.add_argument("--url", default="http://127.0.0.1:9808/status")
    commands.add_parser("demo", help="deterministic failover/failback simulation, with no network changes")
    server = commands.add_parser("server", help="BGP-to-VPC route-server control plane")
    server.add_argument("operation", choices=["validate", "render-frr", "run", "demo", "withdraw"])
    server.add_argument("--config", "-c")
    server.add_argument("--endpoint", help="endpoint ID for render-frr")
    server.add_argument("--apply", action="store_true", help="perform AWS route writes")
    args = parser.parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(message)s")
    try:
        if args.command == "server":
            from .server.cli import execute
            return execute(args)
        if args.command == "demo":
            from .demo import run_demo
            run_demo()
            return 0
        if args.command == "status":
            with urlopen(args.url, timeout=3) as response:
                print(json.dumps(json.load(response), indent=2))
            return 0
        config = load(args.config)
        if args.command == "validate":
            print(f"Valid: {len(config.routes)} prefixes, {sum(len(r.candidates) for r in config.routes)} paths, backend={config.backend.kind}")
        elif args.command == "probe-plan":
            print(probe_plan(config), end="")
        elif args.command == "check-paths":
            asyncio.run(validate_probe_paths(config))
            print("Probe routing checks passed" if config.backend.kind != "aws" else "AWS external probe paths require validation at their vantage points")
        elif args.command == "render-frr":
            print(frr_config(config, args.router_id, args.peer, args.peer_asn, args.med), end="")
        elif args.command == "run":
            asyncio.run(run_daemon(config, args.apply))
        elif args.command == "cleanup-frr":
            if not args.apply:
                raise ConfigError("cleanup-frr requires --apply")
            asyncio.run(cleanup(config))
        return 0
    except (ConfigError, BackendError, OSError, ValueError) as exc:
        print(f"route-discovery: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
