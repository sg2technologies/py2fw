from __future__ import annotations

from collections.abc import Iterable

from py2fw.plugins.base import Exporter


class ExporterRegistry:
    def __init__(self) -> None:
        self._exporters: dict[str, type[Exporter]] = {}

    def register(self, exporter: type[Exporter]) -> None:
        if not exporter.name:
            raise ValueError("exporter name is required")
        self._exporters[exporter.name] = exporter

    def names(self) -> list[str]:
        return sorted(self._exporters)

    def create(self, name: str) -> Exporter:
        try:
            return self._exporters[name]()
        except KeyError as exc:
            raise KeyError(f"unknown target: {name}") from exc


registry = ExporterRegistry()


def register_exporters(exporters: Iterable[type[Exporter]]) -> None:
    for exporter in exporters:
        registry.register(exporter)


def load_builtin_exporters() -> ExporterRegistry:
    from py2fw.exporters.aws.exporter import AwsSecurityGroupExporter
    from py2fw.exporters.azure.exporter import AzureNsgExporter
    from py2fw.exporters.checkpoint.exporter import CheckPointExporter
    from py2fw.exporters.ciscoasa.exporter import CiscoAsaExporter
    from py2fw.exporters.fortigate.exporter import FortiGateExporter
    from py2fw.exporters.iptables.exporter import IptablesExporter
    from py2fw.exporters.kubernetes.exporter import KubernetesNetworkPolicyExporter
    from py2fw.exporters.nftables.exporter import NftablesExporter
    from py2fw.exporters.paloalto.exporter import PaloAltoExporter

    register_exporters(
        [
            IptablesExporter,
            NftablesExporter,
            FortiGateExporter,
            PaloAltoExporter,
            CheckPointExporter,
            CiscoAsaExporter,
            AwsSecurityGroupExporter,
            AzureNsgExporter,
            KubernetesNetworkPolicyExporter,
        ]
    )
    return registry
