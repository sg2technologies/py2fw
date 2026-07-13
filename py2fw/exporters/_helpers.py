from __future__ import annotations

from py2fw.compiler.ir import FirewallIR, PolicyIR, ServiceIR


def address_values(ir: FirewallIR, names: tuple[str, ...]) -> tuple[str, ...]:
    values: list[str] = []
    for name in names:
        address = ir.addresses.get(name)
        values.extend(address.values if address else (name,))
    return tuple(dict.fromkeys(values))


def service_values(ir: FirewallIR, names: tuple[str, ...]) -> tuple[ServiceIR, ...]:
    services = [ir.services[name] for name in names if name in ir.services]
    return tuple(services)


def rule_comment(rule: PolicyIR) -> str:
    return f"# {rule.name} ({rule.id})"
