from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from py2fw.cli._pipeline import compile_path
from py2fw.plugins.registry import load_builtin_exporters
from tests.conftest import make_ir

GOLDEN = Path(__file__).parent / "golden"
TARGETS = load_builtin_exporters().names()


@pytest.mark.parametrize("target", TARGETS)
def test_exporter_matches_golden(target: str) -> None:
    ir = compile_path(Path("examples/basic.yaml"))
    rendered = load_builtin_exporters().create(target).export(ir) + "\n"
    expected = (GOLDEN / f"{target}.txt").read_text(encoding="utf-8")
    assert rendered == expected, f"{target} output drifted from golden file"


def _range_ir() -> object:
    return make_ir(
        objects={"a": ["10.0.0.1"], "b": ["10.0.0.2"]},
        services={"wide": {"protocol": "tcp", "port": "1000-2000"}},
        policies=[
            {
                "name": "r",
                "source": ["a"],
                "destination": ["b"],
                "service": ["wide"],
                "action": "allow",
            }
        ],
    )


def test_port_ranges_are_not_expanded_iptables() -> None:
    rendered = load_builtin_exporters().create("iptables").export(_range_ir())
    assert rendered.count("-A FORWARD") == 1
    assert "--dport 1000:2000" in rendered


def test_port_ranges_use_native_syntax_ciscoasa() -> None:
    rendered = load_builtin_exporters().create("ciscoasa").export(_range_ir())
    assert rendered.strip().count("\n") == 0
    assert "range 1000 2000" in rendered


def test_port_ranges_use_fromport_toport_aws() -> None:
    payload = json.loads(load_builtin_exporters().create("aws-sg").export(_range_ir()))
    perms = payload["SecurityGroupIngress"]
    assert len(perms) == 1
    assert perms[0]["FromPort"] == 1000
    assert perms[0]["ToPort"] == 2000


def test_fortigate_defines_referenced_address_objects() -> None:
    ir = compile_path(Path("examples/basic.yaml"))
    rendered = load_builtin_exporters().create("fortigate").export(ir)
    assert "config firewall address" in rendered
    assert 'edit "web_tier"' in rendered
    assert 'edit "mysql"' in rendered  # service object defined
    assert 'set dstaddr "all"' not in rendered.split("config firewall policy")[0]


def test_azure_resolves_names_to_cidrs() -> None:
    ir = compile_path(Path("examples/basic.yaml"))
    payload = json.loads(load_builtin_exporters().create("azure-nsg").export(ir))
    props = payload["securityRules"][0]["properties"]
    assert props["sourceAddressPrefix"] == "10.10.1.10/32"
    assert props["destinationPortRanges"] == ["3306"]
    assert props["protocol"] == "Tcp"


def test_kubernetes_resolves_names_and_ports() -> None:
    ir = compile_path(Path("examples/basic.yaml"))
    manifest = yaml.safe_load(load_builtin_exporters().create("kubernetes").export(ir))
    ingress = manifest["spec"]["ingress"]
    assert ingress[0]["from"][0]["ipBlock"]["cidr"] == "10.10.1.10/32"
    assert ingress[0]["ports"][0]["port"] == 3306


def test_allow_only_exporter_drops_deny_rules() -> None:
    ir = make_ir(
        objects={"a": ["10.0.0.0/8"], "b": ["10.0.0.2"]},
        services={"ssh": {"protocol": "tcp", "port": 22}},
        policies=[
            {
                "name": "block",
                "source": ["a"],
                "destination": ["b"],
                "service": ["ssh"],
                "action": "deny",
            }
        ],
    )
    payload = json.loads(load_builtin_exporters().create("aws-sg").export(ir))
    assert payload["SecurityGroupIngress"] == []
