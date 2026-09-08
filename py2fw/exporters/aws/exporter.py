from __future__ import annotations

import json

from py2fw.compiler.ir import FirewallIR, ServiceIR
from py2fw.exporters._helpers import Capabilities, address_values, service_values
from py2fw.plugins.base import Exporter


class AwsSecurityGroupExporter(Exporter):
    name = "aws-sg"
    description = "AWS Security Group ingress rules"
    capabilities = Capabilities(allow_only=True)

    def export(self, ir: FirewallIR) -> str:
        permissions: list[dict[str, object]] = []
        for rule in ir.policies:
            if not rule.enabled or rule.action != "allow":
                continue
            ip_ranges = [
                {"CidrIp": "0.0.0.0/0" if src == "any" else src, "Description": rule.name}
                for src in address_values(ir, rule.source)
            ]
            for service in service_values(ir, rule.services):
                permissions.extend(_permissions(service, ip_ranges))
        return json.dumps({"SecurityGroupIngress": permissions}, indent=2)


def _permissions(service: ServiceIR, ip_ranges: list[dict[str, str]]) -> list[dict[str, object]]:
    protocol = "-1" if service.protocol == "any" else service.protocol
    if service.protocol == "any" or service.ports.is_empty or service.ports.is_all_ports:
        return [{"IpProtocol": protocol, "IpRanges": ip_ranges}]
    return [
        {
            "IpProtocol": protocol,
            "FromPort": prange.start,
            "ToPort": prange.end,
            "IpRanges": ip_ranges,
        }
        for prange in service.ports.ranges
    ]
