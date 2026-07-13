from __future__ import annotations

import json

from py2fw.compiler.ir import FirewallIR
from py2fw.plugins.base import Exporter


class AzureNsgExporter(Exporter):
    name = "azure-nsg"
    description = "Azure Network Security Group rules"

    def export(self, ir: FirewallIR) -> str:
        rules = []
        for priority, rule in enumerate(ir.policies, start=100):
            if not rule.enabled:
                continue
            rules.append(
                {
                    "name": rule.name,
                    "properties": {
                        "priority": priority,
                        "direction": "Inbound",
                        "access": "Allow" if rule.action == "allow" else "Deny",
                        "protocol": "*",
                        "sourceAddressPrefix": ",".join(rule.source),
                        "destinationAddressPrefix": ",".join(rule.destination),
                        "destinationPortRange": ",".join(rule.services),
                    },
                }
            )
        return json.dumps({"securityRules": rules}, indent=2)
