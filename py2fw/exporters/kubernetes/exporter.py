from __future__ import annotations

import yaml

from py2fw.compiler.ir import FirewallIR
from py2fw.plugins.base import Exporter


class KubernetesNetworkPolicyExporter(Exporter):
    name = "kubernetes"
    description = "Kubernetes NetworkPolicy manifest"

    def export(self, ir: FirewallIR) -> str:
        ingress = []
        for rule in ir.policies:
            if not rule.enabled or rule.action != "allow":
                continue
            ingress.append(
                {
                    "from": [{"ipBlock": {"cidr": source if source != "any" else "0.0.0.0/0"}} for source in rule.source],
                    "ports": [{"port": service} for service in rule.services],
                }
            )
        manifest = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "py2fw-policy"},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": ingress},
        }
        return yaml.safe_dump(manifest, sort_keys=False)
