from .config import Endpoint, Peer, Propagation, ServerConfig
from .journal import Journal
from .propagation import Propagator
from .rib import LearnedRoute, RIB, Snapshot


def demo_config():
    return ServerConfig("demo", 64512, "eu-west-2", "vpc-0123456789abcdef0",
                        (Endpoint("edge", "10.0.1.5", "10.0.1.5", "/run/frr"),),
                        (Peer("primary", "edge", "10.0.1.10", 65010, "eni-0123456789abcdef0", ("10.0.1.10",), ("10.20.0.0/16",)),
                         Peer("backup", "edge", "10.0.1.20", 65020, "eni-0fedcba9876543210", ("10.0.1.20",), ("10.20.0.0/16",))),
                        (Propagation("rtb-0123456789abcdef0"), Propagation("rtb-0fedcba9876543210")),
                        failback_delay=5, stale_after=10)


async def demo():
    config = demo_config()
    journal = Journal(config)
    rib = RIB(config)
    backend = Propagator(config, journal)
    primary, backup = [LearnedRoute("10.20.1.0/24", p.id, p.endpoint, p.eni, p.next_hops[0], (p.asn,), med, 100)
                       for p, med in zip(config.peers, (10, 100))]
    try:
        for tick, available, title in (
            (0, (primary, backup), "BGP learns two paths"),
            (1, (backup,), "Primary BFD session fails"),
            (2, (primary, backup), "Primary returns; hold-down"),
            (7, (primary, backup), "Stable recovery; failback"),
            (8, (), "Both peers withdraw prefix"),
        ):
            rib.update("edge", Snapshot(available, {p.id: {"up": any(r.peer == p.id for r in available)} for p in config.peers}), tick)
            fib = rib.select(tick)
            assert await backend.reconcile(fib)
            print(f"t={tick:2}s {title}: {', '.join(r.peer for r in fib.values()) or 'withdrawn'}; {len(backend.status)} tables converged")
    finally:
        journal.close()
