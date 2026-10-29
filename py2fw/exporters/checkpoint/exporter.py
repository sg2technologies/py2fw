from __future__ import annotations

import json

from py2fw.compiler.ir import FirewallIR, ServiceIR
from py2fw.compiler.query import resolves_to_any
from py2fw.exporters import _syntax
from py2fw.exporters._helpers import Capabilities
from py2fw.plugins.base import Exporter

_ACTION = {"allow": "Accept", "deny": "Drop", "reject": "Reject"}


class CheckPointExporter(Exporter):
    name = "checkpoint"
    description = "Check Point management API access-rule payloads"
    capabilities = Capabilities(supports_reject=True)

    def check_syntax(self, rendered: str) -> list[str]:
        data, problems = _syntax.json_document(rendered, ["objects", "services", "access_rules"])
        if problems or not isinstance(data, dict):
            return problems
        names = {obj.get("name") for obj in data["objects"]} | {"Any"}
        services = {svc.get("name") for svc in data["services"]} | {"Any"}
        problems += _syntax.unique((obj.get("name") for obj in data["objects"]), "object name")
        problems += _syntax.unique((svc.get("name") for svc in data["services"]), "service name")
        for rule in data["access_rules"]:
            for ref in (*rule.get("source", []), *rule.get("destination", [])):
                if ref not in names:
                    problems.append(f"rule {rule.get('name')}: undefined object {ref}")
            for ref in rule.get("service", []):
                if ref not in services:
                    problems.append(f"rule {rule.get('name')}: undefined service {ref}")
        return problems

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
                "service": [
                    "Any" if n == "any" or ir.services[n].protocol == "any" else n
                    for n in rule.services
                ],
                "action": _ACTION.get(rule.action, "Drop"),
                "enabled": rule.enabled,
                "comments": rule.description,
            }
            for rule in ir.policies
        ]
        services = [
            entry
            for service in ir.services.values()
            if service.name != "any" and service.protocol != "any"
            for entry in _service_objects(service)
        ]
        return json.dumps(
            {"objects": objects, "services": services, "access_rules": rules}, indent=2
        )


def _service_objects(service: ServiceIR) -> list[dict[str, object]]:
    kind = f"service-{service.protocol}"
    if service.protocol == "icmp" or len(service.ports.ranges) <= 1:
        entry: dict[str, object] = {"name": service.name, "type": kind}
        if service.ports.ranges:
            entry["port"] = _port(service.ports.ranges[0].start, service.ports.ranges[0].end)
        return [entry]
    members: list[dict[str, object]] = [
        {"name": f"{service.name}_{index}", "type": kind, "port": _port(r.start, r.end)}
        for index, r in enumerate(service.ports.ranges, start=1)
    ]
    group: dict[str, object] = {
        "name": service.name,
        "type": "service-group",
        "members": [m["name"] for m in members],
    }
    return [*members, group]


def _port(start: int, end: int) -> str:
    return str(start) if start == end else f"{start}-{end}"


def _refs(ir: FirewallIR, names: tuple[str, ...]) -> list[str]:
    return ["Any" if name == "any" or resolves_to_any(ir, (name,)) else name for name in names]
