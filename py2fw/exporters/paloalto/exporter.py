from __future__ import annotations

from py2fw.compiler.ir import FirewallIR
from py2fw.plugins.base import Exporter


class PaloAltoExporter(Exporter):
    name = "paloalto"
    description = "Palo Alto set commands"

    def export(self, ir: FirewallIR) -> str:
        lines: list[str] = []
        for rule in ir.policies:
            if not rule.enabled:
                lines.append(f"# disabled {rule.name}")
                continue
            action = "allow" if rule.action == "allow" else "deny"
            base = f"set rulebase security rules {rule.name}"
            lines.append(f"{base} from any to any")
            lines.append(f"{base} source {' '.join(rule.source)}")
            lines.append(f"{base} destination {' '.join(rule.destination)}")
            lines.append(f"{base} service {' '.join(rule.services)}")
            lines.append(f"{base} application any action {action}")
        return "\n".join(lines)
