from __future__ import annotations

import json

from py2fw.compiler.ir import FirewallIR
from py2fw.plugins.base import Exporter


class CheckPointExporter(Exporter):
    name = "checkpoint"
    description = "Check Point management API payloads"

    def export(self, ir: FirewallIR) -> str:
        payload = [
            {
                "name": rule.name,
                "source": list(rule.source),
                "destination": list(rule.destination),
                "service": list(rule.services),
                "action": "Accept" if rule.action == "allow" else "Drop",
                "enabled": rule.enabled,
            }
            for rule in ir.policies
        ]
        return json.dumps({"access_rules": payload}, indent=2)
