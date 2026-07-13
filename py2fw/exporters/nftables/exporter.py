from __future__ import annotations

from py2fw.compiler.ir import FirewallIR
from py2fw.exporters._helpers import address_values, rule_comment, service_values
from py2fw.plugins.base import Exporter


class NftablesExporter(Exporter):
    name = "nftables"
    description = "Linux nftables rules"

    def export(self, ir: FirewallIR) -> str:
        lines = ["table inet py2fw {", "  chain forward {", "    type filter hook forward priority 0; policy drop;"]
        for rule in ir.policies:
            if not rule.enabled:
                lines.append(f"    # disabled: {rule.name}")
                continue
            verdict = "accept" if rule.action == "allow" else "drop"
            for src in address_values(ir, rule.source):
                for dst in address_values(ir, rule.destination):
                    for service in service_values(ir, rule.services):
                        src_part = "" if src == "any" else f" ip saddr {src}"
                        dst_part = "" if dst == "any" else f" ip daddr {dst}"
                        proto = "" if service.protocol == "any" else f" {service.protocol}"
                        ports = service.ports or (0,)
                        for port in ports:
                            port_part = "" if port == 0 else f" dport {port}"
                            body = " ".join(part for part in [src_part, dst_part, proto.strip() + port_part] if part)
                            lines.append(f"    {body} counter {verdict} comment \"{rule.name}\"")
        lines.extend(["  }", "}"])
        return "\n".join(lines)
