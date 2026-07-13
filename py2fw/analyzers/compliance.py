from __future__ import annotations

from py2fw.analyzers.models import Finding
from py2fw.compiler.ir import FirewallIR


def find_compliance_gaps(ir: FirewallIR) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ir.policies:
        if rule.enabled and not rule.description:
            findings.append(
                Finding(
                    severity="low",
                    title="Missing rule description",
                    rule=rule.name,
                    detail="Descriptions improve auditability and change control.",
                )
            )
    return findings
