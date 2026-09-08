from __future__ import annotations

import json

from py2fw.compiler.ir import FirewallIR, PortRange, ServiceIR
from py2fw.exporters._helpers import Capabilities, address_values, service_values
from py2fw.plugins.base import Exporter

_PROTOCOL = {"tcp": "Tcp", "udp": "Udp", "icmp": "Icmp", "any": "*"}


class AzureNsgExporter(Exporter):
    name = "azure-nsg"
    description = "Azure Network Security Group rules"
    capabilities = Capabilities(supports_reject=False)

    def export(self, ir: FirewallIR) -> str:
        rules: list[dict[str, object]] = []
        priority = 100
        for rule in ir.policies:
            if not rule.enabled:
                continue
            sources = _prefixes(address_values(ir, rule.source))
            destinations = _prefixes(address_values(ir, rule.destination))
            for service in service_values(ir, rule.services):
                rules.append(
                    {
                        "name": f"{rule.name}-{priority}",
                        "properties": {
                            "priority": priority,
                            "direction": "Inbound",
                            "access": "Allow" if rule.action == "allow" else "Deny",
                            "protocol": _PROTOCOL.get(service.protocol, "*"),
                            "sourcePortRange": "*",
                            "destinationPortRanges": _port_ranges(service),
                            **_prefix_field("source", sources),
                            **_prefix_field("destination", destinations),
                        },
                    }
                )
                priority += 1
        return json.dumps({"securityRules": rules}, indent=2)


def _prefixes(values: tuple[str, ...]) -> list[str]:
    return ["*" if v == "any" else v for v in values]


def _prefix_field(kind: str, prefixes: list[str]) -> dict[str, object]:
    if len(prefixes) == 1:
        return {f"{kind}AddressPrefix": prefixes[0]}
    return {f"{kind}AddressPrefixes": prefixes}


def _port_range(prange: PortRange) -> str:
    return str(prange.start) if prange.is_single else f"{prange.start}-{prange.end}"


def _port_ranges(service: ServiceIR) -> list[str]:
    if service.ports.is_empty or service.ports.is_all_ports:
        return ["*"]
    return [_port_range(r) for r in service.ports.ranges]
