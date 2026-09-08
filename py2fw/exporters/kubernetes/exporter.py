from __future__ import annotations

import yaml

from py2fw.compiler.ir import FirewallIR, PortRange, ServiceIR
from py2fw.exporters._helpers import Capabilities, address_values, service_values
from py2fw.plugins.base import Exporter

_PROTOCOL = {"tcp": "TCP", "udp": "UDP"}


class KubernetesNetworkPolicyExporter(Exporter):
    name = "kubernetes"
    description = "Kubernetes NetworkPolicy manifest"
    capabilities = Capabilities(allow_only=True)

    def export(self, ir: FirewallIR) -> str:
        ingress: list[dict[str, object]] = []
        for rule in ir.policies:
            if not rule.enabled or rule.action != "allow":
                continue
            peers = [
                {"ipBlock": {"cidr": "0.0.0.0/0" if src == "any" else src}}
                for src in address_values(ir, rule.source)
            ]
            ports: list[dict[str, object]] = []
            for service in service_values(ir, rule.services):
                ports.extend(_ports(service))
            ingress.append({"from": peers, "ports": ports})
        manifest = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "py2fw-policy"},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": ingress},
        }
        rendered: str = yaml.safe_dump(manifest, sort_keys=False)
        return rendered


def _ports(service: ServiceIR) -> list[dict[str, object]]:
    protocol = _PROTOCOL.get(service.protocol)
    if protocol is None or service.ports.is_empty or service.ports.is_all_ports:
        return []
    return [_port_entry(protocol, r) for r in service.ports.ranges]


def _port_entry(protocol: str, prange: PortRange) -> dict[str, object]:
    entry: dict[str, object] = {"protocol": protocol, "port": prange.start}
    if not prange.is_single:
        entry["endPort"] = prange.end
    return entry
