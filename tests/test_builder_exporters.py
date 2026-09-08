from __future__ import annotations

from py2fw.compiler.builder import build_ir
from py2fw.compiler.ir import PortRange
from py2fw.exporters.iptables.exporter import IptablesExporter
from py2fw.parser.schema import PolicyDocument
from py2fw.plugins.registry import load_builtin_exporters


def _document() -> PolicyDocument:
    return PolicyDocument.model_validate(
        {
            "version": 1,
            "objects": {"web": ["10.0.0.1"], "db": ["10.0.0.2"]},
            "groups": {"tier": ["web"]},
            "services": {"mysql": {"protocol": "tcp", "port": 3306}},
            "policies": [
                {
                    "name": "web_to_db",
                    "source": ["tier"],
                    "destination": ["db"],
                    "service": ["mysql"],
                    "action": "allow",
                }
            ],
        }
    )


def test_build_ir_resolves_groups() -> None:
    ir = build_ir(_document())

    assert ir.addresses["tier"].values == ("10.0.0.1/32",)
    assert ir.services["mysql"].ports.contains(3306)
    assert ir.services["mysql"].ports.ranges == (PortRange(3306, 3306),)


def test_iptables_exporter_uses_ir() -> None:
    rendered = IptablesExporter().export(build_ir(_document()))

    assert "-A FORWARD" in rendered
    assert "--dport 3306" in rendered


def test_builtin_targets_are_registered() -> None:
    names = load_builtin_exporters().names()

    assert "fortigate" in names
    assert "aws-sg" in names
    assert "kubernetes" in names
