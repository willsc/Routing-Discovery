#!/usr/bin/env python3
"""Real FRR BGP learning/withdrawal in a private network namespace; no AWS calls.

Use --frr-root for an extracted distribution package, or / for installed FRR.
This uses bgpd's no-zebra mode only in the isolated test harness.
"""

import argparse
import asyncio
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from route_discovery.commands import run
from route_discovery.server.config import Endpoint
from route_discovery.server.demo import demo_config
from route_discovery.server.frr import FRRSource, render
from route_discovery.server.journal import Journal
from route_discovery.server.propagation import Propagator
from route_discovery.server.rib import RIB


async def smoke(root):
    processes, logs = [], []
    with tempfile.TemporaryDirectory(prefix="rd-frr-") as directory:
        directory = Path(directory)
        bgpd = root / "usr/lib/frr/bgpd"
        vtysh = root / "usr/bin/vtysh"
        library = root / "usr/lib/x86_64-linux-gnu"
        env = os.environ | {"LD_LIBRARY_PATH": f"{library}:{library / 'frr'}"}
        await run("ip", "link", "set", "lo", "up")
        for index in (1, 2, 3):
            await run("ip", "addr", "add", f"198.18.0.{index}/32", "dev", "lo")
        config = demo_config()
        config = replace(config, endpoints=(Endpoint("edge", "198.18.0.1", "198.18.0.1", str(directory / "edge")),),
                         peers=tuple(replace(p, address=f"198.18.0.{i}", next_hops=(f"198.18.0.{i}",), bfd=False)
                                     for i, p in enumerate(config.peers, 2)), failback_delay=0.3)

        async def runner(*args, **kwargs):
            if args[0] == "vtysh":
                # Extracted packages lack host PAM configuration. Speak the same local
                # VTY command protocol directly in this harness; production uses vtysh.
                folder = args[args.index("--vty_socket") + 1]
                commands = [args[i + 1] for i, value in enumerate(args) if value == "-c"]
                reader, writer = await asyncio.open_unix_connection(str(Path(folder) / "bgpd.vty"))
                output = []
                try:
                    for command in ["enable", *commands]:
                        writer.write(command.encode() + b"\0")
                        await writer.drain()
                        data = await asyncio.wait_for(reader.readuntil(b"\0\0\0"), 3)
                        code = await reader.readexactly(1)
                        if code != b"\0":
                            raise RuntimeError(f"FRR command failed: {command}: {data[:-3].decode()}")
                        if command != "enable":
                            output.append(data[:-3].decode())
                    return "".join(output)
                finally:
                    writer.close()
                    await writer.wait_closed()
            return await run(*args, **kwargs)

        def start(label, address, content):
            folder = directory / label
            folder.mkdir()
            file = folder / "bgpd.conf"
            file.write_text(content)
            log = (folder / "bgpd.log").open("w+")
            logs.append(log)
            process = subprocess.Popen([str(bgpd), "-S", "-Z", "-n", "-l", address, "-f", str(file),
                                        "--vty_socket", str(folder), "-i", str(folder / "bgpd.pid"), "-P", "0",
                                        "--log", "stdout"], env=env, stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)

        source = FRRSource(config, runner)
        rib = RIB(config)
        journal = Journal(config)
        backend = Propagator(config, journal)

        async def expect(paths, winner=None):
            last = None
            async with asyncio.timeout(20):
                while True:
                    try:
                        snapshot = await source.read(config.endpoints[0])
                        rib.update("edge", snapshot, asyncio.get_running_loop().time())
                        fib = rib.select(asyncio.get_running_loop().time())
                        if len(snapshot.routes) == paths and (winner is None or any(r.peer == winner for r in fib.values())):
                            assert await backend.reconcile(fib)
                            return snapshot
                        last = (snapshot, fib)
                    except Exception as exc:
                        last = exc
                    if any(p.poll() is not None for p in processes):
                        raise RuntimeError(f"FRR exited; last observation: {last}")
                    await asyncio.sleep(0.1)

        try:
            server_config = render(config, "edge").replace(" bgp no-rib", " bgp disable-ebgp-connected-route-check")
            start("edge", "198.18.0.1", server_config)
            for peer, med in zip(config.peers, (10, 100)):
                content = f"""route-map OUT permit 10
 set metric {med}
router bgp {peer.asn}
 bgp router-id {peer.address}
 no bgp ebgp-requires-policy
 no bgp network import-check
 bgp disable-ebgp-connected-route-check
 neighbor 198.18.0.1 remote-as {config.asn}
 neighbor 198.18.0.1 update-source {peer.address}
 neighbor 198.18.0.1 timers 1 3
 address-family ipv4 unicast
  network 10.20.1.0/24
  neighbor 198.18.0.1 route-map OUT out
 exit-address-family
"""
                start(peer.id, peer.address, content)
            await expect(2, "primary")
            await runner("vtysh", "--vty_socket", str(directory / "primary"), "-c", "configure terminal",
                         "-c", "router bgp 65010", "-c", "address-family ipv4 unicast", "-c", "no network 10.20.1.0/24")
            await expect(1, "backup")
            await runner("vtysh", "--vty_socket", str(directory / "primary"), "-c", "configure terminal",
                         "-c", "router bgp 65010", "-c", "address-family ipv4 unicast", "-c", "network 10.20.1.0/24")
            await expect(2, "primary")
            for peer in config.peers:
                await runner("vtysh", "--vty_socket", str(directory / peer.id), "-c", "configure terminal",
                             "-c", f"router bgp {peer.asn}", "-c", "address-family ipv4 unicast", "-c", "no network 10.20.1.0/24")
            await expect(0)
            assert not journal.entries()
            print("PASS: real FRR BGP learning, primary withdrawal, backup selection, failback and two-table simulated propagation")
        except Exception:
            for command in ("show bgp summary json", "show bgp ipv4 unicast json"):
                try:
                    print(command + ":\n" + await runner("vtysh", "--vty_socket", str(directory / "edge"), "-c", command), file=sys.stderr)
                except Exception as exc:
                    print(str(exc), file=sys.stderr)
            for log in logs:
                log.flush()
                log.seek(0)
                print(log.name + ":\n" + log.read()[-6000:], file=sys.stderr)
            raise
        finally:
            for process in processes:
                process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for log in logs:
                log.close()
            journal.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--frr-root", default="/")
    parser.add_argument("--parent-netns")
    args = parser.parse_args()
    inode = str(os.stat("/proc/self/ns/net").st_ino)
    if args.parent_netns is None:
        result = subprocess.run(["unshare", "--user", "--map-root-user", "--net", sys.executable, str(Path(__file__).resolve()),
                                 "--frr-root", args.frr_root, "--parent-netns", inode])
        raise SystemExit(result.returncode)
    if args.parent_netns == inode:
        raise SystemExit("refusing to run in the host network namespace")
    asyncio.run(smoke(Path(args.frr_root)))
