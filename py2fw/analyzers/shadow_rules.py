from __future__ import annotations

from py2fw.analyzers.duplicate_rules import fingerprint
from py2fw.analyzers.models import Finding
from py2fw.compiler.ir import FirewallIR


def find_shadowed_rules(ir: FirewallIR) -> list[Finding]:
    seen: dict[tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str], str] = {}
    findings: list[Finding] = []
    for rule in ir.policies:
        any_action_key = (rule.source, rule.destination, rule.services, "allow" if rule.action != "allow" else "deny")
        exact_key = fingerprint(rule)
        if any_action_key in seen:
            findings.append(
                Finding(
                    severity="medium",
                    title="Shadowed rule",
                    rule=rule.name,
                    detail=f"Overlaps earlier opposite action rule {seen[any_action_key]}",
                )
            )
        seen[exact_key] = rule.name
    return findings
