from __future__ import annotations

import json

from py2fw.compiler.ir import FirewallIR
from py2fw.exporters._helpers import address_values, service_values
from py2fw.plugins.base import Exporter


class AwsSecurityGroupExporter(Exporter):
    name = "aws-sg"
    description = "AWS Security Group ingress rules"

    def export(self, ir: FirewallIR) -> str:
        permissions: list[dict[str, object]] = []
        for rule in ir.policies:
            if not rule.enabled or rule.action != "allow":
                continue
            for dst_service in service_values(ir, rule.services):
                ports = dst_service.ports or (0,)
                for port in ports:
                    permissions.append(
                        {
                            "IpProtocol": "-1" if dst_service.protocol == "any" else dst_service.protocol,
                            "FromPort": None if port == 0 else port,
                            "ToPort": None if port == 0 else port,
                            "IpRanges": [
                                {"CidrIp": src if src != "any" else "0.0.0.0/0", "Description": rule.name}
                                for src in address_values(ir, rule.source)
                            ],
                        }
                    )
        return json.dumps({"SecurityGroupIngress": permissions}, indent=2)
