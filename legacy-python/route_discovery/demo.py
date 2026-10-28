from .config import Candidate, Config, Health, Probe, Route
from .policy import Policy


def run_demo():
    route = Route("10.20.0.0/16", (
        Candidate("primary", (Probe("192.0.2.10", 443),), local_pref=200),
        Candidate("backup", (Probe("192.0.2.20", 443),), local_pref=100),
    ))
    config = Config((route,), health=Health(failures=3, successes=2, failback_delay=5))
    policy = Policy(config)
    last = None
    print("Simulation: primary fails at t=4s, recovers at t=10s; failback hold-down is 5s.")
    for tick in range(18):
        for c in route.candidates:
            ok = c.id != "primary" or not 4 <= tick < 10
            policy.health[route.prefix, c.id].observe(ok, tick, config.health)
        decision = policy.select(route, tick)
        policy.commit(route, decision)
        current = (decision.action, decision.paths)
        if current != last:
            print(f"t={tick:2}s  {decision.action:8}  {','.join(decision.paths) or '-':12}  {decision.reason}")
            last = current
