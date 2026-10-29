from __future__ import annotations

from py2fw.analyzers.models import Finding, rule_finding
from py2fw.compiler.ir import FirewallIR


def find_documentation_gaps(ir: FirewallIR) -> list[Finding]:
    """Enabled rules with no description have no recorded business justification."""

    findings: list[Finding] = []
    for rule in ir.policies:
        if rule.enabled and not rule.description:
            findings.append(
                rule_finding(
                    rule,
                    "low",
                    "Missing business justification",
                    "Add a description stating why this access is needed.",
                )
            )
    return findings
