from __future__ import annotations

from py2fw.analyzers.models import Finding
from py2fw.compiler.ir import FirewallIR


def _expand(names: set[str], groups: dict[str, tuple[str, ...]]) -> set[str]:
    """Add every transitive group member of ``names`` to the set."""

    frontier = list(names)
    while frontier:
        current = frontier.pop()
        for member in groups.get(current, ()):
            if member not in names:
                names.add(member)
                frontier.append(member)
    return names


def find_unused_objects(ir: FirewallIR) -> list[Finding]:
    used = {"any"}
    for rule in ir.policies:
        used.update(rule.source)
        used.update(rule.destination)
    _expand(used, ir.groups)
    findings: list[Finding] = []
    for name in sorted(set(ir.addresses) - used):
        address = ir.addresses.get(name)
        findings.append(
            Finding(
                severity="low",
                title="Unused object",
                detail=name,
                line=address.line if address else None,
                location=f"objects.{name}",
            )
        )
    return findings


def find_unused_services(ir: FirewallIR) -> list[Finding]:
    used = {"any"}
    for rule in ir.policies:
        used.update(rule.services)
    findings: list[Finding] = []
    for name in sorted(set(ir.services) - used):
        service = ir.services.get(name)
        findings.append(
            Finding(
                severity="low",
                title="Unused service",
                detail=name,
                line=service.line if service else None,
                location=f"services.{name}",
            )
        )
    return findings
