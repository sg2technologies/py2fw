from __future__ import annotations

from py2fw.analyzers.models import Finding
from py2fw.compiler.ir import FirewallIR, PolicyIR
from py2fw.exporters._helpers import address_values, service_values
from py2fw.utils.constants import DATABASE_PORTS, HIGH_RISK_PORTS


def _has_any_to_any(ir: FirewallIR, rule: PolicyIR) -> bool:
    return "any" in address_values(ir, rule.source) and "any" in address_values(ir, rule.destination)


def find_attack_surface(ir: FirewallIR) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ir.policies:
        if not rule.enabled:
            findings.append(Finding(severity="medium", title="Disabled rule", rule=rule.name))
            continue
        if rule.action != "allow":
            continue
        services = service_values(ir, rule.services)
        ports = {port for service in services for port in service.ports}
        if _has_any_to_any(ir, rule):
            findings.append(Finding(severity="high", title="Any to Any", rule=rule.name))
        for port, title in HIGH_RISK_PORTS.items():
            if port in ports and "any" in address_values(ir, rule.source):
                findings.append(Finding(severity="high", title=title, rule=rule.name))
        if ports & DATABASE_PORTS and "any" in address_values(ir, rule.source):
            findings.append(
                Finding(
                    severity="high",
                    title="Internet to internal database",
                    rule=rule.name,
                    detail=f"Database ports: {sorted(ports & DATABASE_PORTS)}",
                )
            )
    return findings
