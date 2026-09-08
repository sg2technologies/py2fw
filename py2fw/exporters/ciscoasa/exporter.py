from __future__ import annotations

from py2fw.compiler.ir import FirewallIR, PortRange, ServiceIR
from py2fw.exporters._helpers import Capabilities, address_values, service_values
from py2fw.plugins.base import Exporter


class CiscoAsaExporter(Exporter):
    name = "ciscoasa"
    description = "Cisco ASA access-list entries"
    capabilities = Capabilities(supports_ipv6=True)

    def export(self, ir: FirewallIR) -> str:
        lines: list[str] = []
        for rule in ir.policies:
            if not rule.enabled:
                lines.append(f"! disabled {rule.name}")
                continue
            action = "permit" if rule.action == "allow" else "deny"
            for src in address_values(ir, rule.source):
                for dst in address_values(ir, rule.destination):
                    for service in service_values(ir, rule.services):
                        proto = "ip" if service.protocol == "any" else service.protocol
                        for port_part in _port_parts(service):
                            lines.append(
                                f"access-list PY2FW extended {action} {proto} "
                                f"{_endpoint(src)} {_endpoint(dst)}{port_part}".rstrip()
                            )
        return "\n".join(lines)


def _endpoint(value: str) -> str:
    if value == "any":
        return "any"
    return value if "/" in value else f"host {value}"


def _port_range(prange: PortRange) -> str:
    return f" eq {prange.start}" if prange.is_single else f" range {prange.start} {prange.end}"


def _port_parts(service: ServiceIR) -> list[str]:
    if service.ports.is_empty or service.ports.is_all_ports:
        return [""]
    return [_port_range(r) for r in service.ports.ranges]
