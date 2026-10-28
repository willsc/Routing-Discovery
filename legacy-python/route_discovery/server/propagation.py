"""Propagate learned FIB routes into explicitly associated VPC route tables."""

import asyncio
import ipaddress

from ..commands import BackendError
from .config import permits


def ec2_client(config):
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise BackendError("Install route-discovery[aws] to apply VPC routes") from exc
    return boto3.client("ec2", region_name=config.region, config=Config(
        connect_timeout=2, read_timeout=3, retries={"mode": "standard", "total_max_attempts": 2}))


class Propagator:
    def __init__(self, config, journal, client=None, apply=False):
        self.config = config
        self.journal = journal
        self.apply = apply
        self.client = client if client is not None else ec2_client(config) if apply else None
        self.simulated = {}
        self.status = {}
        self.changes = 0
        self.failures = 0

    async def verify_targets(self):
        if not self.apply:
            return
        ids = sorted({p.eni for p in self.config.peers})
        response = await asyncio.to_thread(self.client.describe_network_interfaces, NetworkInterfaceIds=ids)
        interfaces = {e["NetworkInterfaceId"]: e for e in response.get("NetworkInterfaces", [])}
        for peer in self.config.peers:
            eni = interfaces.get(peer.eni)
            if not eni or eni.get("VpcId") != self.config.vpc_id or eni.get("Status") != "in-use":
                raise BackendError(f"{peer.id}: ENI must be attached in the associated VPC")
            if eni.get("SourceDestCheck") is not False:
                raise BackendError(f"{peer.id}: forwarding ENI must have source/destination checking disabled")
            addresses = {x["PrivateIpAddress"] for x in eni.get("PrivateIpAddresses", [])}
            addresses |= {x["Ipv6Address"] for x in eni.get("Ipv6Addresses", [])}
            if not set(peer.next_hops) <= addresses:
                raise BackendError(f"{peer.id}: configured next hops do not belong to its ENI")

    async def table(self, table_id):
        if not self.apply:
            return self.simulated.setdefault(table_id, {})
        response = await asyncio.to_thread(self.client.describe_route_tables, RouteTableIds=[table_id])
        tables = response.get("RouteTables", [])
        if len(tables) != 1 or tables[0].get("RouteTableId") != table_id:
            raise BackendError(f"route table {table_id} missing")
        table = tables[0]
        if table.get("VpcId") != self.config.vpc_id:
            raise BackendError(f"{table_id}: route table is outside the associated VPC")
        tags = {t["Key"]: t["Value"] for t in table.get("Tags", [])}
        if tags.get(self.config.owner_tag) != self.config.id:
            raise BackendError(f"{table_id}: missing ownership tag {self.config.owner_tag}={self.config.id}")
        if any(a.get("GatewayId", "").startswith("vgw-") for a in table.get("Associations", [])):
            raise BackendError("virtual-private-gateway route tables are not supported")
        result = {}
        for route in table.get("Routes", []):
            prefix = route.get("DestinationCidrBlock", route.get("DestinationIpv6CidrBlock"))
            if prefix:
                result[prefix] = route
        return result

    @staticmethod
    def owned(record, targets):
        return (record.get("Origin") == "CreateRoute" and record.get("NetworkInterfaceId") in targets
                and record.get("GatewayId") != "local")

    async def mutate(self, table_id, prefix, target, before):
        if not self.apply:
            table = self.simulated.setdefault(table_id, {})
            if target is None:
                table.pop(prefix, None)
            else:
                table[prefix] = {"Origin": "CreateRoute", "State": "active", "NetworkInterfaceId": target}
            return
        dest = "DestinationCidrBlock" if ipaddress.ip_network(prefix).version == 4 else "DestinationIpv6CidrBlock"
        kwargs = {"RouteTableId": table_id, dest: prefix}
        if target is None:
            method = self.client.delete_route
        else:
            kwargs["NetworkInterfaceId"] = target
            method = self.client.create_route if before is None else self.client.replace_route
        response = await asyncio.to_thread(method, **kwargs)
        if response.get("Return") is False:
            raise BackendError("AWS route mutation returned false")

    async def reconcile(self, fib, guard=lambda: True):
        # Verify the mapping on every pass; do not keep routing to reassigned ENI addresses.
        await self.verify_targets()
        propagation_map = {t.table: t for t in self.config.propagations}
        tables = set(propagation_map) | {table for table, _ in self.journal.entries()}
        for table_id in sorted(tables):
            target = propagation_map.get(table_id)
            desired = {prefix: route.eni for prefix, route in fib.items()
                       if target and target.enabled and (not target.allowed_prefixes or permits(prefix, target.allowed_prefixes))}
            state = {"enabled": bool(target and target.enabled), "converged": False, "routes": {}, "error": None}
            self.status[table_id] = state
            try:
                if target and len(desired) > target.max_routes:
                    raise BackendError(f"{table_id}: FIB exceeds configured max_routes")
                observed = await self.table(table_id)
                entries = self.journal.entries()
                prefixes = sorted(set(desired) | {prefix for table, prefix in entries if table == table_id})
                for prefix in prefixes:
                    if not guard():
                        raise BackendError("learned-route generation changed; defer remaining writes")
                    before = observed.get(prefix)
                    wanted = desired.get(prefix)
                    owned_targets = entries.get((table_id, prefix))
                    try:
                        if before is not None and (owned_targets is None or not self.owned(before, owned_targets)):
                            raise BackendError("route is not journal-owned; refusing to overwrite/delete it")
                        correct = before is not None and before.get("NetworkInterfaceId") == wanted and before.get("State") == "active"
                        if wanted is not None and not correct:
                            # Write-ahead intent covers a crash after AWS succeeds but before readback.
                            self.journal.intent(table_id, prefix, wanted)
                            await self.mutate(table_id, prefix, wanted, before)
                            self.changes += 1
                        elif wanted is None and before is not None:
                            await self.mutate(table_id, prefix, None, before)
                            self.changes += 1
                        state["routes"][prefix] = {"desired": wanted, "converged": False, "error": None}
                    except Exception as exc:
                        self.failures += 1
                        state["routes"][prefix] = {"desired": wanted, "converged": False, "error": str(exc)}
                # Verify independently of API return codes, including delayed deletions.
                after = await self.table(table_id)
                for prefix, result in state["routes"].items():
                    current = after.get(prefix)
                    if result["error"]:
                        continue
                    if result["desired"] is None:
                        result["converged"] = current is None
                        if current is None:
                            self.journal.forget(table_id, prefix)
                    else:
                        result["converged"] = bool(current and current.get("State") == "active" and
                                                   current.get("NetworkInterfaceId") == result["desired"] and
                                                   self.owned(current, self.journal.entries().get((table_id, prefix), set())))
                    result["observed"] = current.get("NetworkInterfaceId") if current else None
                state["converged"] = all(r["converged"] for r in state["routes"].values())
            except Exception as exc:
                self.failures += 1
                state["error"] = str(exc)
        return all(s["converged"] for s in self.status.values())
