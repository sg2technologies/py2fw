from __future__ import annotations

import ipaddress

from py2fw.analyzers.models import Finding, rule_finding
from py2fw.compiler.ir import FirewallIR, PolicyIR
from py2fw.compiler.query import address_values, service_values
from py2fw.utils.constants import BROAD_PREFIX_MAX_LEN, DATABASE_PORTS, HIGH_RISK_PORTS


def _is_broad_source(values: tuple[str, ...]) -> bool:
    """True if the source covers 'any' or an over-large public prefix."""

    for value in values:
        if value == "any":
            return True
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if not net.is_private and net.prefixlen <= BROAD_PREFIX_MAX_LEN[net.version]:
            return True
    return False


def _covers_port(ir: FirewallIR, rule: PolicyIR, port: int) -> bool:
    return any(svc.ports.contains(port) for svc in service_values(ir, rule.services))


def _covered_ports(ir: FirewallIR, rule: PolicyIR, ports: frozenset[int]) -> set[int]:
    matched: set[int] = set()
    for svc in service_values(ir, rule.services):
        matched |= svc.ports.matching(ports)
    return matched


def find_attack_surface(ir: FirewallIR) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ir.policies:
        if not rule.enabled:
            findings.append(rule_finding(rule, "medium", "Disabled rule"))
            continue
        if rule.action != "allow":
            continue

        source_values = address_values(ir, rule.source)
        dest_values = address_values(ir, rule.destination)
        broad_source = _is_broad_source(source_values)

        if broad_source and "any" in dest_values:
            findings.append(rule_finding(rule, "high", "Any to Any"))

        if broad_source:
            for port, title in HIGH_RISK_PORTS.items():
                if _covers_port(ir, rule, port):
                    findings.append(rule_finding(rule, "high", title))
            exposed_db = _covered_ports(ir, rule, DATABASE_PORTS)
            if exposed_db:
                findings.append(
                    rule_finding(
                        rule,
                        "high",
                        "Internet to internal database",
                        f"Database ports: {sorted(exposed_db)}",
                    )
                )
            if any(svc.ports.is_all_ports for svc in service_values(ir, rule.services)):
                findings.append(
                    rule_finding(
                        rule,
                        "high",
                        "Broad source to all ports",
                        "Rule allows every port from an untrusted source.",
                    )
                )
    return findings
