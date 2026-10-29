from __future__ import annotations

from abc import ABC, abstractmethod

from py2fw.compiler.ir import FirewallIR
from py2fw.exporters._helpers import Capabilities


class Exporter(ABC):
    name: str
    description: str = ""
    capabilities: Capabilities = Capabilities()

    @abstractmethod
    def export(self, ir: FirewallIR) -> str:
        """Export a vendor-neutral IR to vendor-specific configuration."""

    def check_syntax(self, rendered: str) -> list[str]:
        """Return problems that make ``rendered`` malformed for this target (built-in check)."""

        return []

    def native_checks(self, rendered: str) -> list[tuple[tuple[str, ...], str]]:
        """Vendor tools that can validate ``rendered``: ``(command, stdin)`` pairs."""

        return []
