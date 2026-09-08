from __future__ import annotations

from collections.abc import Callable

from py2fw.compiler.ir import FirewallIR, PortRange
from py2fw.exporters._helpers import Capabilities
from py2fw.plugins.base import Exporter


class PaloAltoExporter(Exporter):
    name = "paloalto"
    description = "Palo Alto PAN-OS set commands"
    capabilities = Capabilities(supports_reject=True)

    def export(self, ir: FirewallIR) -> str:
        referenced = _referenced(ir)
        lines: list[str] = []
        resolve = _address_lines(ir, referenced, lines)
        _service_lines(ir, lines)

        for rule in ir.policies:
            if not rule.enabled:
                lines.append(f"# disabled {rule.name}")
                continue
            action = {"allow": "allow", "deny": "deny", "reject": "reset-both"}.get(
                rule.action, "deny"
            )
            base = f"set rulebase security rules {rule.name}"
            lines.append(f"{base} from any to any")
            lines.append(f"{base} source [ {' '.join(resolve(n) for n in rule.source)} ]")
            lines.append(f"{base} destination [ {' '.join(resolve(n) for n in rule.destination)} ]")
            lines.append(f"{base} service [ {' '.join(_svc(n) for n in rule.services)} ]")
            lines.append(f"{base} application any action {action}")
        return "\n".join(lines)


def _referenced(ir: FirewallIR) -> set[str]:
    names: set[str] = set()
    for rule in ir.policies:
        names.update(rule.source)
        names.update(rule.destination)
    return names


def _address_lines(
    ir: FirewallIR, referenced: set[str], lines: list[str]
) -> Callable[[str], str]:
    resolved: dict[str, str] = {}
    for name in sorted(referenced):
        address = ir.addresses.get(name)
        values = address.values if address else (name,)
        if values == ("any",):
            resolved[name] = "any"
            continue
        if len(values) == 1:
            lines.append(f"set address {name} ip-netmask {values[0]}")
            resolved[name] = name
            continue
        members = []
        for idx, value in enumerate(values, start=1):
            member = f"{name}-{idx}"
            lines.append(f"set address {member} ip-netmask {value}")
            members.append(member)
        lines.append(f"set address-group {name} static [ {' '.join(members)} ]")
        resolved[name] = name
    return lambda ref: resolved.get(ref, ref)


def _pan_port(prange: PortRange) -> str:
    return str(prange.start) if prange.is_single else f"{prange.start}-{prange.end}"


def _service_lines(ir: FirewallIR, lines: list[str]) -> None:
    for name, service in ir.services.items():
        if name == "any" or service.protocol not in {"tcp", "udp"}:
            continue
        if service.ports.is_empty or service.ports.is_all_ports:
            continue
        ports = ",".join(_pan_port(r) for r in service.ports.ranges)
        lines.append(f"set service {name} protocol {service.protocol} port {ports}")


def _svc(name: str) -> str:
    return "any" if name == "any" else name
