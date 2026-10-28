from dataclasses import replace

from route_discovery.config import Backend, Candidate, Config, Health, Probe, Route


def configuration(kind="linux", **health):
    candidates = (
        Candidate("primary", (Probe("10.20.0.10", 443, device="wg-a", mark=10101),),
                  device="wg-a", aws_target="eni-0123456789abcdef0", local_pref=200),
        Candidate("backup", (Probe("10.20.0.10", 443, device="wg-b", mark=10102),),
                  device="wg-b", aws_target="eni-0fedcba9876543210", local_pref=100),
    )
    return Config((Route("10.20.0.0/16", candidates),),
                  health=replace(Health(), **health),
                  backend=Backend(kind=kind, region="eu-west-2", route_table_id="rtb-0123456789abcdef0"))
