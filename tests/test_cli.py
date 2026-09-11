from __future__ import annotations

from pathlib import Path

from py2fw.main import app
from typer.testing import CliRunner

runner = CliRunner()
BASIC = "examples/basic.yaml"


def test_simulate_allowed() -> None:
    result = runner.invoke(
        app, ["simulate", BASIC, "--src", "10.10.1.10", "--dst", "10.10.2.10", "--port", "3306"]
    )
    assert result.exit_code == 0
    assert "ALLOWED" in result.stdout


def test_simulate_denied_exit_code() -> None:
    result = runner.invoke(
        app, ["simulate", BASIC, "--src", "10.10.1.10", "--dst", "10.10.2.10", "--port", "22"]
    )
    assert result.exit_code == 1
    assert "DENIED" in result.stdout


def test_explain_flow_trace() -> None:
    result = runner.invoke(
        app, ["explain", BASIC, "--src", "10.10.1.10", "--dst", "10.10.2.10", "--port", "3306"]
    )
    assert result.exit_code == 0
    assert "web_to_db" in result.stdout


def test_compile_refuses_lossy_without_flag(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "version: 1\n"
        "objects:\n  a: [10.0.0.0/8]\n  b: [10.0.0.2]\n"
        "services:\n  ssh: {protocol: tcp, port: 22}\n"
        "policies:\n"
        "  - {name: block, source: [a], destination: [b], service: [ssh], action: deny}\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["compile", str(policy), "--target", "aws-sg"])
    assert result.exit_code == 3
    ok = runner.invoke(app, ["compile", str(policy), "--target", "aws-sg", "--allow-lossy"])
    assert ok.exit_code == 0


def test_compile_unknown_target() -> None:
    result = runner.invoke(app, ["compile", BASIC, "--target", "nope"])
    assert result.exit_code == 2


def test_diff_reports_changes(tmp_path: Path) -> None:
    v2 = tmp_path / "v2.yaml"
    v2.write_text(Path(BASIC).read_text(encoding="utf-8"), encoding="utf-8")
    v2.write_text(
        v2.read_text(encoding="utf-8")
        + "\n  - {name: new, source: [internet], destination: [db], service: [https], "
        "action: allow}\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["diff", BASIC, str(v2)])
    assert result.exit_code == 0
    assert "+ new" in result.stdout
    assert "Security impact" in result.stdout


def test_compliance_reports_and_exits_on_fail() -> None:
    result = runner.invoke(app, ["compliance", "examples/risky.yaml"])
    assert result.exit_code == 1
    assert "PCI DSS" in result.stdout
    assert "FAIL" in result.stdout


def test_compliance_framework_filter() -> None:
    result = runner.invoke(app, ["compliance", "examples/basic.yaml", "-f", "cis"])
    assert "CIS Controls" in result.stdout
    assert "PCI DSS" not in result.stdout


def test_compliance_unknown_framework() -> None:
    result = runner.invoke(app, ["compliance", "examples/basic.yaml", "-f", "hipaa"])
    assert result.exit_code == 2


def test_validate_shows_line_numbers(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "version: 1\nobjects:\n  web: [10.0.0.1]\n  bad:\n    - nope!!\n", encoding="utf-8"
    )
    result = runner.invoke(app, ["validate", str(policy)])
    assert result.exit_code == 1
    assert "p.yaml:5" in result.stdout


def test_validate_bad_policy_exit_code(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text("version: 1\nobjects:\n  bad: [\"not valid\"]\n", encoding="utf-8")
    result = runner.invoke(app, ["validate", str(policy)])
    assert result.exit_code == 1
