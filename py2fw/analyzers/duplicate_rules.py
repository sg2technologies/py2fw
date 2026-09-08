from __future__ import annotations

from py2fw.analyzers.models import Finding, rule_finding
from py2fw.compiler.ir import FirewallIR, PolicyIR


def fingerprint(rule: PolicyIR) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str]:
    return (rule.source, rule.destination, rule.services, rule.action)


def find_duplicate_rules(ir: FirewallIR) -> list[Finding]:
    seen: dict[tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str], str] = {}
    findings: list[Finding] = []
    for rule in ir.policies:
        key = fingerprint(rule)
        if key in seen:
            findings.append(
                rule_finding(rule, "medium", "Duplicate rule", f"Duplicates {seen[key]}")
            )
        else:
            seen[key] = rule.name
    return findings
