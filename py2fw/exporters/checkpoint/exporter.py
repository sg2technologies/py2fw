from __future__ import annotations

import json

from py2fw.compiler.ir import FirewallIR
from py2fw.compiler.query import resolves_to_any
from py2fw.exporters._helpers import Capabilities
from py2fw.plugins.base import Exporter

_ACTION = {"allow": "Accept", "deny": "Drop", "reject": "Reject"}


class CheckPointExporter(Exporter):
    name = "checkpoint"
    description = "Check Point management API access-rule payloads"
    capabilities = Capabilities(supports_reject=True)

    def export(self, ir: FirewallIR) -> str:
        objects = [
            {"name": address.name, "type": "network-list", "members": list(address.values)}
            for address in ir.addresses.values()
            if address.values != ("any",)
        ]
        rules = [
            {
                "name": rule.name,
                "source": _refs(ir, rule.source),
                "destination": _refs(ir, rule.destination),
                "service": ["Any" if n == "any" else n for n in rule.services],
                "action": _ACTION.get(rule.action, "Drop"),
                "enabled": rule.enabled,
                "comments": rule.description,
            }
            for rule in ir.policies
        ]
        return json.dumps({"objects": objects, "access_rules": rules}, indent=2)


def _refs(ir: FirewallIR, names: tuple[str, ...]) -> list[str]:
    return ["Any" if name == "any" or resolves_to_any(ir, (name,)) else name for name in names]
