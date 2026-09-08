"""Read-only helpers for querying a compiled :class:`FirewallIR`.

Shared by exporters and analyzers so neither has to reach into the other.
"""

from __future__ import annotations

from py2fw.compiler.ir import FirewallIR, ServiceIR


def address_values(ir: FirewallIR, names: tuple[str, ...]) -> tuple[str, ...]:
    """Resolve address/group names to their canonical values, de-duplicated."""

    values: list[str] = []
    for name in names:
        address = ir.addresses.get(name)
        values.extend(address.values if address else (name,))
    return tuple(dict.fromkeys(values))


def resolves_to_any(ir: FirewallIR, names: tuple[str, ...]) -> bool:
    return "any" in address_values(ir, names)


def service_values(ir: FirewallIR, names: tuple[str, ...]) -> tuple[ServiceIR, ...]:
    return tuple(ir.services[name] for name in names if name in ir.services)
