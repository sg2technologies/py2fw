from __future__ import annotations

from py2fw.compiler.ir import FirewallIR
from py2fw.exporters._helpers import address_values, rule_comment, service_values
from py2fw.plugins.base import Exporter


class IptablesExporter(Exporter):
    name = "iptables"
    description = "Linux iptables rules"

    def export(self, ir: FirewallIR) -> str:
        lines = ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD DROP [0:0]", ":OUTPUT ACCEPT [0:0]"]
        for rule in ir.policies:
            if not rule.enabled:
                lines.append(f"{rule_comment(rule)} disabled")
                continue
            target = "ACCEPT" if rule.action == "allow" else "DROP"
            for src in address_values(ir, rule.source):
                for dst in address_values(ir, rule.destination):
                    for service in service_values(ir, rule.services):
                        proto = "" if service.protocol == "any" else f" -p {service.protocol}"
                        ports = service.ports or (0,)
                        for port in ports:
                            dport = "" if port == 0 else f" --dport {port}"
                            src_arg = "" if src == "any" else f" -s {src}"
                            dst_arg = "" if dst == "any" else f" -d {dst}"
                            lines.append(rule_comment(rule))
                            lines.append(f"-A FORWARD{proto}{src_arg}{dst_arg}{dport} -j {target}")
        lines.append("COMMIT")
        return "\n".join(lines)
