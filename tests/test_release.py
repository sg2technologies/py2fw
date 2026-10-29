from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
from py2fw.main import app
from py2fw.release.audit import append_event, verify_log
from py2fw.release.plan import (
    ReleaseError,
    StatePaths,
    approve_plan,
    create_plan,
    deploy_plan,
    load_plan,
    save_plan,
)
from typer.testing import CliRunner

runner = CliRunner()
BASELINE = Path("examples/baseline.yaml")


@pytest.fixture
def workspace(tmp_path: Path) -> tuple[Path, StatePaths]:
    policy = tmp_path / "prod.yaml"
    shutil.copyfile("examples/prod.yaml", policy)
    return policy, StatePaths(tmp_path / "state")


def _plan(policy: Path, state: StatePaths, target: str = "paloalto") -> dict[str, object]:
    return create_plan(policy, target, author="alice", baseline=BASELINE, state=state)


def _approved(policy: Path, state: StatePaths) -> dict[str, object]:
    plan = _plan(policy, state)
    approve_plan(plan, "bob", state=state)
    approve_plan(plan, "carol", state=state)
    return plan


def test_plan_records_gate_verification_and_diff(workspace: tuple[Path, StatePaths]) -> None:
    policy, state = workspace
    plan = _plan(policy, state)
    content = plan["content"]
    assert content["deployable"]
    assert content["required_approvals"] == 2
    assert content["config_diff"].startswith("--- /dev/null")
    assert all(check["passed"] for check in content["verification"])


def test_author_cannot_self_approve(workspace: tuple[Path, StatePaths]) -> None:
    policy, state = workspace
    with pytest.raises(ReleaseError, match="author"):
        approve_plan(_plan(policy, state), "alice", state=state)


def test_deploy_requires_quorum(workspace: tuple[Path, StatePaths], tmp_path: Path) -> None:
    policy, state = workspace
    plan = _plan(policy, state)
    approve_plan(plan, "bob", state=state)
    with pytest.raises(ReleaseError) as exc:
        deploy_plan(plan, actor="ci", destination=tmp_path / "out.cfg", state=state)
    assert any("1 of 2" in reason for reason in exc.value.reasons)
    assert not (tmp_path / "out.cfg").exists()


def test_deploy_writes_config_and_audits(
    workspace: tuple[Path, StatePaths], tmp_path: Path
) -> None:
    policy, state = workspace
    plan = _approved(policy, state)
    out = tmp_path / "out" / "pa.cfg"
    result = deploy_plan(plan, actor="ci", destination=out, state=state)
    assert result.approvers == ("bob", "carol")
    assert out.read_text().startswith("set address")
    events = [json.loads(line)["event"] for line in state.audit_log.read_text().splitlines()]
    assert events == ["plan", "approve", "approve", "deploy"]
    assert verify_log(state.audit_log).ok
    replan = _plan(policy, state)
    assert replan["content"]["config_diff"] == ""
    assert replan["content"]["policy_changes"] == ["security impact: NONE"]


def test_policy_change_after_approval_blocks_deploy(
    workspace: tuple[Path, StatePaths], tmp_path: Path
) -> None:
    policy, state = workspace
    plan = _approved(policy, state)
    policy.write_text(policy.read_text().replace("port: 443 }", "port: 8443 }"))
    with pytest.raises(ReleaseError) as exc:
        deploy_plan(plan, actor="ci", destination=tmp_path / "out.cfg", state=state)
    assert "policy changed since the plan was approved" in exc.value.reasons


def test_edited_plan_file_is_rejected(workspace: tuple[Path, StatePaths], tmp_path: Path) -> None:
    policy, state = workspace
    path = tmp_path / "plan.json"
    plan = _approved(policy, state)
    plan["content"]["config"]["text"] += "\nset rulebase security rules evil action allow"
    save_plan(plan, path)
    with pytest.raises(ReleaseError, match="modified"):
        load_plan(path)


def test_signed_approvals(
    workspace: tuple[Path, StatePaths], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, state = workspace
    baseline = tmp_path / "baseline.yaml"
    baseline.write_text(
        BASELINE.read_text().replace("required_approvals: 2", "required_approvals: 1\n"
                                     "    sign_approvals: true")
    )
    plan = create_plan(policy, "paloalto", author="alice", baseline=baseline, state=state)
    with pytest.raises(ReleaseError, match="PY2FW_APPROVAL_KEY"):
        approve_plan(plan, "bob", state=state)
    monkeypatch.setenv("PY2FW_APPROVAL_KEY", "approver-secret")
    approve_plan(plan, "bob", state=state)
    forged = {"by": "mallory", "at": "", "comment": "", "signature": "0" * 64}
    plan["approvals"] = [forged]
    with pytest.raises(ReleaseError):
        deploy_plan(plan, actor="ci", destination=tmp_path / "x.cfg", state=state)
    plan["approvals"] = []
    approve_plan(plan, "bob", state=state)
    assert deploy_plan(plan, actor="ci", destination=tmp_path / "x.cfg", state=state).approvers


def test_deploy_runs_command(workspace: tuple[Path, StatePaths], tmp_path: Path) -> None:
    policy, state = workspace
    plan = _approved(policy, state)
    copy = tmp_path / "applied.cfg"
    script = f"import shutil,sys; shutil.copyfile(sys.argv[1], {str(copy)!r})"
    command = f'"{sys.executable}" -c "{script}" {{config}}'
    deploy_plan(plan, actor="ci", command=command, state=state)
    assert copy.read_text().startswith("set address")


def test_failed_deploy_command_is_audited(
    workspace: tuple[Path, StatePaths], tmp_path: Path
) -> None:
    policy, state = workspace
    plan = _approved(policy, state)
    command = f'"{sys.executable}" -c "import sys; sys.exit(3)"'
    with pytest.raises(ReleaseError, match="exited with 3"):
        deploy_plan(plan, actor="ci", command=command, state=state)
    last = json.loads(state.audit_log.read_text().splitlines()[-1])
    assert last["event"] == "deploy_failed"


def test_audit_log_detects_tampering(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    for actor in ("alice", "bob", "carol"):
        append_event(log, "approve", actor)
    assert verify_log(log).ok
    lines = log.read_text().splitlines()
    log.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert not verify_log(log).ok


def test_cli_release_flow(workspace: tuple[Path, StatePaths], tmp_path: Path) -> None:
    policy, state = workspace
    plan_file = tmp_path / "plan.json"
    common = ["--state-dir", str(state.root)]
    result = runner.invoke(
        app,
        ["plan", str(policy), "-t", "paloalto", "--author", "alice", "-b", str(BASELINE),
         "-o", str(plan_file), *common],
    )
    assert result.exit_code == 0, result.output
    assert runner.invoke(app, ["approve", str(plan_file), "--by", "alice", *common]).exit_code == 6
    for approver in ("bob", "carol"):
        approved = runner.invoke(app, ["approve", str(plan_file), "--by", approver, *common])
        assert approved.exit_code == 0
    out = tmp_path / "deployed.cfg"
    result = runner.invoke(
        app, ["deploy", str(plan_file), "--actor", "ci", "--to", str(out), *common]
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert runner.invoke(app, ["audit", "verify", *common]).exit_code == 0
