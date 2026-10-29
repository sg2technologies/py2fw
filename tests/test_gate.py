from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import pytest
from py2fw.analyzers.engine import analyze_ir
from py2fw.analyzers.gate import VIOLATION, WAIVED, WARNING, evaluate_gate
from py2fw.cli._pipeline import validate_path
from py2fw.main import app
from py2fw.parser.yaml_parser import ParseError, parse_policy_with_source
from tests.conftest import make_ir
from typer.testing import CliRunner

runner = CliRunner()
TODAY = date(2026, 6, 1)

OPEN_SSH = {
    "objects": {"internet": ["any"], "bastion": ["10.0.0.5"]},
    "services": {"ssh": {"protocol": "tcp", "port": 22}},
    "policies": [
        {"name": "ssh_in", "source": ["internet"], "destination": ["bastion"],
         "service": ["ssh"], "action": "allow", "description": "Admin access."}
    ],
}


def _gate(fail_on: str = "high", **document: Any):
    ir = make_ir(**document)
    return evaluate_gate(ir, analyze_ir(ir), fail_on=fail_on, today=TODAY)


def _verdicts(gate: Any, title: str) -> list[str]:
    return [item.verdict for item in gate.items if item.finding.title == title]


def _exception(**overrides: Any) -> dict[str, Any]:
    waiver = {"rule": "ssh_in", "finding": "Open SSH", "reason": "Bastion, MFA enforced",
              "expires": "2026-12-31", "ticket": "SEC-42"}
    waiver.update(overrides)
    return waiver


# --- YAML validation -------------------------------------------------------


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text("version: 1\nobjects:\n  db: [10.0.0.1]\n  db: [0.0.0.0/0]\n")
    with pytest.raises(ParseError, match="duplicate key 'db' at line 4"):
        parse_policy_with_source(policy)


def test_schema_errors_report_line(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "version: 1\npolicies:\n  - name: a\n    source: [any]\n    destination: [any]\n"
        "    service: [any]\n    action: alow\n"
    )
    with pytest.raises(ParseError, match=r"policies\[0\]\.action \(line 7\)"):
        parse_policy_with_source(policy)


def test_exception_must_reference_existing_rule(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "version: 1\nexceptions:\n  - {rule: ghost, finding: Open SSH, reason: x, "
        "expires: 2026-12-31}\n"
    )
    _, result = validate_path(policy)
    assert not result.ok
    assert any("unknown rule: ghost" in issue.message for issue in result.issues)


def test_exception_requires_reason(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "version: 1\nexceptions:\n  - {rule: a, finding: b, reason: ' ', expires: 2026-12-31}\n"
    )
    with pytest.raises(ParseError, match="reason"):
        parse_policy_with_source(policy)


# --- risky rule detection --------------------------------------------------


def test_internal_risky_scope_findings() -> None:
    ir = make_ir(
        objects={"app": ["10.0.1.0/24"], "db": ["10.0.2.10"]},
        services={"ephemeral": {"protocol": "tcp", "port": "1024-65535"},
                  "ftp": {"protocol": "tcp", "port": 21}},
        policies=[
            {"name": "all", "source": ["app"], "destination": ["db"], "service": ["any"],
             "action": "allow"},
            {"name": "wide", "source": ["app"], "destination": ["db"], "service": ["ephemeral"],
             "action": "allow"},
            {"name": "egress", "source": ["app"], "destination": ["any"], "service": ["ftp"],
             "action": "allow"},
        ],
    )
    found = {(f.rule, f.title, f.severity) for f in analyze_ir(ir).findings}
    assert ("all", "Allows all services", "medium") in found
    assert ("wide", "Wide port range", "medium") in found
    assert ("egress", "Any destination", "medium") in found
    assert ("egress", "Cleartext protocol", "low") in found


def test_any_to_any_is_critical() -> None:
    ir = make_ir(
        objects={"internet": ["any"]},
        policies=[{"name": "open", "source": ["internet"], "destination": ["any"],
                   "service": ["any"], "action": "allow"}],
    )
    assert any(f.title == "Any to Any" and f.severity == "critical"
               for f in analyze_ir(ir).findings)


# --- warning vs violation --------------------------------------------------


def test_high_finding_is_violation_low_is_warning() -> None:
    gate = _gate(**OPEN_SSH)
    assert not gate.passed
    assert _verdicts(gate, "Open SSH") == [VIOLATION]


def test_fail_on_threshold_changes_classification() -> None:
    doc = {**OPEN_SSH, "policies": [{**OPEN_SSH["policies"][0], "description": ""}]}
    assert _verdicts(_gate(**doc), "Missing rule description") == [WARNING]
    assert _verdicts(_gate("low", **doc), "Missing rule description") == [VIOLATION]
    assert _gate("critical", **doc).passed


def test_valid_exception_waives_violation() -> None:
    gate = _gate(**OPEN_SSH, exceptions=[_exception()])
    assert gate.passed
    item = next(i for i in gate.items if i.finding.title == "Open SSH")
    assert item.verdict == WAIVED
    assert "SEC-42" in item.note


def test_expired_exception_blocks() -> None:
    gate = _gate(**OPEN_SSH, exceptions=[_exception(expires="2026-01-01")])
    assert not gate.passed
    item = next(i for i in gate.items if i.finding.title == "Open SSH")
    assert "expired" in item.note


def test_critical_findings_cannot_be_waived() -> None:
    gate = _gate(
        objects={"internet": ["any"]},
        policies=[{"name": "open", "source": ["internet"], "destination": ["any"],
                   "service": ["any"], "action": "allow", "description": "x"}],
        exceptions=[_exception(rule="open", finding="Any to Any")],
    )
    assert not gate.passed
    assert _verdicts(gate, "Any to Any") == [VIOLATION]


def test_unused_exception_is_warning() -> None:
    gate = _gate(**OPEN_SSH, exceptions=[_exception(), _exception(finding="Open RDP")])
    assert _verdicts(gate, "Unused exception") == [WARNING]


# --- production gate -------------------------------------------------------


def test_check_command_exit_codes() -> None:
    assert runner.invoke(app, ["check", "examples/basic.yaml"]).exit_code == 0
    result = runner.invoke(app, ["check", "examples/basic.yaml", "examples/risky.yaml"])
    assert result.exit_code == 1
    assert "FAIL risky.yaml" in result.stdout


def test_check_json_output() -> None:
    result = runner.invoke(app, ["check", "examples/risky.yaml", "--json"])
    assert result.exit_code == 1
    assert '"passed": false' in result.stdout


def test_compile_refuses_unsafe_policy() -> None:
    result = runner.invoke(app, ["compile", "examples/risky.yaml", "--target", "iptables"])
    assert result.exit_code == 4
    assert "-A" not in result.stdout


def test_compile_allows_waived_policy(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "version: 1\n"
        "objects:\n  internet: [any]\n  bastion: [10.0.0.5]\n"
        "services:\n  ssh: {protocol: tcp, port: 22}\n"
        "policies:\n"
        "  - {name: ssh_in, source: [internet], destination: [bastion], service: [ssh],\n"
        "     action: allow, description: Admin access.}\n"
        "exceptions:\n"
        "  - {rule: ssh_in, finding: Open SSH, reason: Bastion with MFA, expires: 2099-12-31}\n"
    )
    result = runner.invoke(app, ["compile", str(policy), "--target", "iptables"])
    assert result.exit_code == 0, result.output
