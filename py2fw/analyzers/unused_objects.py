from __future__ import annotations

from py2fw.analyzers.models import Finding
from py2fw.compiler.ir import FirewallIR


def find_unused_objects(ir: FirewallIR) -> list[Finding]:
    used = {"any"}
    for rule in ir.policies:
        used.update(rule.source)
        used.update(rule.destination)
    return [
        Finding(severity="low", title="Unused object", rule=None, detail=name)
        for name in sorted(set(ir.addresses) - used)
    ]


def find_unused_services(ir: FirewallIR) -> list[Finding]:
    used = {"any"}
    for rule in ir.policies:
        used.update(rule.services)
    return [
        Finding(severity="low", title="Unused service", rule=None, detail=name)
        for name in sorted(set(ir.services) - used)
    ]
