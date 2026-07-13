from __future__ import annotations

from py2fw.compiler.ir import FirewallIR
from py2fw.plugins.base import Exporter


class FortiGateExporter(Exporter):
    name = "fortigate"
    description = "FortiGate CLI configuration"

    def export(self, ir: FirewallIR) -> str:
        lines = ["config firewall policy"]
        for index, rule in enumerate(ir.policies, start=1):
            if not rule.enabled:
                lines.append(f"    # disabled {rule.name}")
                continue
            action = "accept" if rule.action == "allow" else "deny"
            lines.extend(
                [
                    f"    edit {index}",
                    f"        set name \"{rule.name}\"",
                    "        set srcintf \"any\"",
                    "        set dstintf \"any\"",
                    f"        set srcaddr {' '.join(f'\"{x}\"' for x in rule.source)}",
                    f"        set dstaddr {' '.join(f'\"{x}\"' for x in rule.destination)}",
                    f"        set service {' '.join(f'\"{x}\"' for x in rule.services)}",
                    f"        set action {action}",
                    "        set schedule \"always\"",
                    "        set logtraffic all",
                    "    next",
                ]
            )
        lines.append("end")
        return "\n".join(lines)
