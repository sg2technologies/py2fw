from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import pytest
from py2fw.analyzers.engine import analyze_ir
from py2fw.analyzers.gate import VIOLATION, WAIVED, evaluate_gate
from py2fw.analyzers.shadow_rules import find_shadowed_rules
from py2fw.cli._pipeline import check_path, render_config, validate_path
from py2fw.enforcement.baseline import (
    BaselineError,
    BaselineModel,
    enforce_baseline,
    resolve_controls,
)
from py2fw.main import app
from py2fw.parser.schema import FlowTestModel
from py2fw.plugins.registry import load_builtin_exporters
from py2fw.verify.config import check_intent
from py2fw.verify.regression import run_flow_tests
from tests.conftest import make_ir
from typer.testing import CliRunner

runner = CliRunner()
TODAY = date(2026, 6, 1)
BASELINE = Path("examples/baseline.yaml")
PROD = Path("examples/prod.yaml")

SSH_DOC: dict[str, Any] = {
    "objects": {"internet": ["any"], "bastion": ["10.0.0.5"]},
    "services": {"ssh": {"protocol": "tcp", "port": 22}},
    "policies": [
        {"name": "ssh_in", "source": ["internet"], "destination": ["bastion"],
         "service": ["ssh"], "action": "allow", "description": "Admin access."}
    ],
    "exceptions": [
        {"rule": "ssh_in", "finding": "Open SSH", "reason": "Bastion", "expires": "2026-12-31"}
    ],
}


def _baseline(**environments: Any) -> BaselineModel:
    return BaselineModel.model_validate(
        {
            "version": 1,
            "defaults": {
                "fail_on": "high",
                "forbidden": [{"name": "no-telnet", "ports": [23], "severity": "critical"}],
            },
            "environments": environments,
        }
    )


# --- stage 3: semantic validation ------------------------------------------


def test_conflicting_rules_are_flagged() -> None:
    ir = make_ir(
        objects={"a": ["10.0.0.0/24"], "b": ["10.0.0.128/25"], "db": ["10.1.0.5"]},
        services={"web": {"protocol": "tcp", "port": "80-443"},
                  "https": {"protocol": "tcp", "port": 443}},
        policies=[
            {"name": "deny_b", "source": ["b"], "destination": ["db"], "service": ["https"],
             "action": "deny"},
            {"name": "allow_a", "source": ["a"], "destination": ["db"], "service": ["web"],
             "action": "allow"},
        ],
    )
    findings = find_shadowed_rules(ir)
    assert [(f.rule, f.title) for f in findings] == [("allow_a", "Conflicting rules")]


def test_cidr_with_host_bits_warns(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text("version: 1\nobjects:\n  net: [10.0.0.5/24]\n")
    _, result = validate_path(policy)
    assert result.ok
    assert any("host bits" in issue.message for issue in result.issues)


def test_admin_port_winrm_from_internet() -> None:
    ir = make_ir(
        objects={"internet": ["any"], "srv": ["10.0.0.9"]},
        services={"winrm": {"protocol": "tcp", "port": 5986}},
        policies=[{"name": "w", "source": ["internet"], "destination": ["srv"],
                   "service": ["winrm"], "action": "allow"}],
    )
    assert any(f.title == "Open WinRM" for f in analyze_ir(ir).findings)


# --- stage 4: baseline and environments ------------------------------------


def test_environment_overrides_and_extends_defaults() -> None:
    baseline = _baseline(
        prod={"fail_on": "medium", "forbidden": [{"name": "no-http", "ports": [80]}]}
    )
    prod = resolve_controls(baseline, "prod", baseline_sha256="x")
    assert prod.fail_on == "medium"
    assert [f.name for f in prod.forbidden] == ["no-telnet", "no-http"]
    assert resolve_controls(baseline, "", baseline_sha256="x").fail_on == "high"


def test_unknown_environment_is_rejected() -> None:
    with pytest.raises(BaselineError, match="unknown environment 'qa'"):
        resolve_controls(_baseline(prod={}), "qa")


def test_forbidden_pattern_and_required_fields() -> None:
    ir = make_ir(
        objects={"a": ["10.0.0.1"], "b": ["10.0.0.2"]},
        services={"telnet": {"protocol": "tcp", "port": 23}},
        policies=[{"name": "t", "source": ["a"], "destination": ["b"], "service": ["telnet"],
                   "action": "allow", "owner": "ops"}],
    )
    controls = resolve_controls(
        _baseline(prod={"require_fields": ["owner", "ticket"]}), "prod", baseline_sha256="x"
    )
    found = {(f.title, f.severity) for f in enforce_baseline(ir, controls)}
    assert found == {("Baseline: no-telnet", "critical"), ("Baseline: missing ticket", "high")}


def test_cli_fail_on_cannot_loosen_baseline() -> None:
    ir = make_ir(**SSH_DOC)
    controls = resolve_controls(_baseline(prod={"fail_on": "medium"}), "prod", baseline_sha256="x")
    gate = evaluate_gate(ir, analyze_ir(ir), fail_on="critical", controls=controls, today=TODAY)
    assert gate.fail_on == "medium"


@pytest.mark.parametrize(
    ("settings", "note"),
    [({"allow_exceptions": False}, "not permitted"), ({"max_exception_days": 30}, "30-day")],
)
def test_environment_restricts_exceptions(settings: dict[str, Any], note: str) -> None:
    ir = make_ir(**SSH_DOC)
    controls = resolve_controls(_baseline(prod=settings), "prod", baseline_sha256="x")
    gate = evaluate_gate(ir, analyze_ir(ir), controls=controls, today=TODAY)
    item = next(i for i in gate.items if i.finding.title == "Open SSH")
    assert item.verdict == VIOLATION
    assert note in item.note
    relaxed = evaluate_gate(ir, analyze_ir(ir), today=TODAY)
    assert next(i for i in relaxed.items if i.finding.title == "Open SSH").verdict == WAIVED


def test_policy_environment_must_match_cli(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="does not match"):
        check_path(PROD, baseline=BASELINE, environment="dev")


def test_prod_example_passes_prod_baseline() -> None:
    check = check_path(PROD, baseline=BASELINE)
    assert check.gate.passed, [i.finding.title for i in check.gate.items]
    assert check.controls.required_approvals == 2
    assert len(check.gate.tests) == 6


def test_risky_example_fails_prod_baseline() -> None:
    result = runner.invoke(
        app, ["check", "examples/risky.yaml", "--baseline", str(BASELINE), "--env", "prod"]
    )
    assert result.exit_code == 1
    assert "Baseline: no-admin-from-internet" in result.stdout


# --- stage 6: configuration validation & regression tests ------------------


def _flow_test(**fields: Any) -> FlowTestModel:
    return FlowTestModel.model_validate({"name": "t", "port": 22, **fields})


def test_regression_tests_probe_objects_and_wildcards() -> None:
    ir = make_ir(
        objects={"internet": ["any"], "web": ["10.0.1.0/24"], "db": ["10.0.2.10"]},
        services={"ssh": {"protocol": "tcp", "port": 22}},
        policies=[{"name": "ssh", "source": ["web"], "destination": ["db"], "service": ["ssh"],
                   "action": "allow"}],
    )
    passing = run_flow_tests(ir, [_flow_test(src="internet", dst="*", expect="deny")], "baseline")
    assert passing[0].passed
    failing = run_flow_tests(ir, [_flow_test(src="web", dst="db", expect="deny")], "policy")
    assert not failing[0].passed
    assert "allow by ssh" in failing[0].detail


def test_failed_regression_test_blocks(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(
        PROD.read_text().replace("port: 5432, expect: deny", "port: 5432, expect: allow")
    )
    check = check_path(policy, baseline=BASELINE)
    assert not check.gate.passed
    assert any("Regression test failed: db-not-public" == i.finding.title
               for i in check.gate.by_verdict(VIOLATION))


def test_test_endpoint_must_be_ip_or_object(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text("version: 1\ntests:\n  - {name: t, src: ghost, dst: '*', port: 1, "
                      "expect: deny}\n")
    _, result = validate_path(policy)
    assert not result.ok


@pytest.mark.parametrize("target", load_builtin_exporters().names())
def test_generated_config_verifies_and_corruption_is_caught(target: str) -> None:
    check = check_path(PROD)
    rendered = render_config(check.ir, target)
    assert rendered.verified, rendered.checks
    exporter = rendered.exporter
    assert exporter.check_syntax(rendered.text + "\n}}} garbage {")
    injected = rendered.text.replace("10.20.1.0", "10.99.99.0")
    assert not check_intent(check.ir, exporter, injected).passed


def test_compile_refuses_unapproved_target() -> None:
    result = runner.invoke(
        app, ["compile", str(PROD), "-t", "iptables", "--baseline", str(BASELINE)]
    )
    assert result.exit_code == 4


def test_verify_command() -> None:
    result = runner.invoke(app, ["verify", str(PROD), "-t", "nftables"])
    assert result.exit_code == 0
    assert "intent: matches policy" in result.stdout


def test_native_syntax_runs_vendor_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    from py2fw.verify.config import check_syntax

    exporter = load_builtin_exporters().create("nftables")
    rejects = ((sys.executable, "-c", "import sys; sys.stderr.write('bad'); sys.exit(1)"), "")
    monkeypatch.setattr(exporter, "native_checks", lambda rendered: [rejects])
    native = check_syntax(exporter, "", native=True)[-1]
    assert native.kind == "native-syntax" and not native.passed and "bad" in native.detail

    monkeypatch.setattr(exporter, "native_checks", lambda rendered: [(("no-such-nft",), "")])
    assert "not found" in check_syntax(exporter, "", native=True)[-1].detail
