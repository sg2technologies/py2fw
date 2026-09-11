from __future__ import annotations

import ipaddress

from py2fw.analyzers.duplicate_rules import fingerprint
from py2fw.analyzers.models import Finding, rule_finding
from py2fw.compiler.ir import FirewallIR, PolicyIR, PortRange, PortSpec
from py2fw.compiler.query import address_values, service_values

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _networks(values: tuple[str, ...]) -> list[Network]:
    nets: list[Network] = []
    for value in values:
        if value == "any":
            nets.append(ipaddress.ip_network("0.0.0.0/0"))
            nets.append(ipaddress.ip_network("::/0"))
            continue
        try:
            nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return nets


def _subnet_of(inner: Network, outer: Network) -> bool:
    if inner.version != outer.version:
        return False
    return inner.subnet_of(outer)  # type: ignore[arg-type]


def _covers_addresses(outer: tuple[str, ...], inner: tuple[str, ...]) -> bool:
    outer_nets = _networks(outer)
    inner_nets = _networks(inner)
    if not inner_nets:
        return False
    return all(any(_subnet_of(i, o) for o in outer_nets) for i in inner_nets)


def _port_spec_for(ir: FirewallIR, names: tuple[str, ...]) -> tuple[set[str], PortSpec]:
    protocols: set[str] = set()
    ranges: list[PortRange] = []
    for svc in service_values(ir, names):
        protocols.add(svc.protocol)
        ranges.extend(svc.ports.ranges)
    return protocols, PortSpec.from_pairs((r.start, r.end) for r in ranges)


def _covers_services(ir: FirewallIR, outer: PolicyIR, inner: PolicyIR) -> bool:
    outer_protos, outer_ports = _port_spec_for(ir, outer.services)
    inner_protos, inner_ports = _port_spec_for(ir, inner.services)
    if "any" in outer_protos:
        return True
    if not inner_protos <= outer_protos:
        return False
    if outer_ports.is_all_ports or outer_ports.is_empty and inner_ports.is_empty:
        return True
    return all(
        outer_ports.contains(r.start) and outer_ports.contains(r.end)
        for r in inner_ports.ranges
    )


def _subsumes(ir: FirewallIR, outer: PolicyIR, inner: PolicyIR) -> bool:
    return (
        _covers_addresses(address_values(ir, outer.source), address_values(ir, inner.source))
        and _covers_addresses(
            address_values(ir, outer.destination), address_values(ir, inner.destination)
        )
        and _covers_services(ir, outer, inner)
    )


def find_shadowed_rules(ir: FirewallIR) -> list[Finding]:
    findings: list[Finding] = []
    enabled = [rule for rule in ir.policies if rule.enabled]
    for i, rule in enumerate(enabled):
        for earlier in enabled[:i]:
            if not _subsumes(ir, earlier, rule):
                continue
            if earlier.action == rule.action:
                if fingerprint(earlier) == fingerprint(rule):
                    continue  # exact duplicate; reported by find_duplicate_rules
                findings.append(
                    rule_finding(
                        rule,
                        "low",
                        "Redundant rule",
                        f"Fully covered by earlier rule {earlier.name} with the same action",
                    )
                )
            else:
                findings.append(
                    rule_finding(
                        rule,
                        "medium",
                        "Shadowed rule",
                        f"Never reached; earlier rule {earlier.name} "
                        f"({earlier.action}) already decides this traffic",
                    )
                )
            break
    return findings
