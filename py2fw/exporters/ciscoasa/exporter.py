from __future__ import annotations

from py2fw.compiler.ir import FirewallIR
from py2fw.exporters._helpers import address_values, service_values
from py2fw.plugins.base import Exporter


class CiscoAsaExporter(Exporter):
    name = "ciscoasa"
    description = "Cisco ASA access-list entries"

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
                        ports = service.ports or (0,)
                        for port in ports:
                            src_part = "any" if src == "any" else f"host {src}" if "/" not in src else src
                            dst_part = "any" if dst == "any" else f"host {dst}" if "/" not in dst else dst
                            port_part = "" if port == 0 else f" eq {port}"
                            lines.append(f"access-list PY2FW extended {action} {proto} {src_part} {dst_part}{port_part}")
        return "\n".join(lines)
