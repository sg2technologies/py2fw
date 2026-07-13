from __future__ import annotations

from abc import ABC, abstractmethod

from py2fw.compiler.ir import FirewallIR


class Exporter(ABC):
    name: str
    description: str = ""

    @abstractmethod
    def export(self, ir: FirewallIR) -> str:
        """Export a vendor-neutral IR to vendor-specific configuration."""
