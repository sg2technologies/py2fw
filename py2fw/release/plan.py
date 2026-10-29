"""Review, approval and controlled deployment.

``plan``    gate + verify a policy for one target and environment, diff the
            generated config against what was last deployed, and write a plan
            file whose ``plan_id`` is the SHA-256 of its content.
``approve`` add a named approval to a plan. The author cannot approve their own
            plan; approvals are HMAC-signed when ``PY2FW_APPROVAL_KEY`` is set.
``deploy``  re-run every check against the files on disk, confirm they still
            match what was approved, require the environment's approval quorum,
            then write the config (and optionally hand it to a deploy command).

Every step is appended to the hash-chained audit log in the state directory.
"""

from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import os
import shlex
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from py2fw.analyzers.gate import VIOLATION, WAIVED, WARNING
from py2fw.cli._pipeline import (
    PolicyCheck,
    RenderedConfig,
    check_path,
    compile_path,
    render_config,
    sha256_file,
)
from py2fw.engine.diff import diff_policies
from py2fw.release.audit import append_event, canonical

PLAN_FORMAT = "py2fw-plan/1"
APPROVAL_KEY_VAR = "PY2FW_APPROVAL_KEY"
DEFAULT_STATE_DIR = Path(".py2fw")


class ReleaseError(ValueError):
    """Raised when a plan cannot be created, approved or deployed."""

    def __init__(self, message: str, reasons: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.reasons = reasons


@dataclass(frozen=True, slots=True)
class StatePaths:
    root: Path

    @property
    def audit_log(self) -> Path:
        return self.root / "audit.jsonl"

    def deployed_config(self, environment: str, target: str) -> Path:
        return self.root / "deployed" / (environment or "default") / f"{target}.cfg"

    def deployed_policy(self, environment: str, target: str) -> Path:
        return self.root / "deployed" / (environment or "default") / f"{target}.policy.yaml"


def plan_id(content: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(content).encode("utf-8")).hexdigest()


def _sign(plan_hash: str, approver: str) -> str:
    key = os.environ.get(APPROVAL_KEY_VAR, "")
    if not key:
        return ""
    message = f"{plan_hash}:{approver}".encode()
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _gate_summary(check: PolicyCheck) -> dict[str, Any]:
    gate = check.gate
    return {
        "passed": gate.passed,
        "fail_on": gate.fail_on,
        "violations": [item.finding.title for item in gate.by_verdict(VIOLATION)],
        "waived": [
            {"rule": item.finding.rule, "finding": item.finding.title, "note": item.note}
            for item in gate.by_verdict(WAIVED)
        ],
        "warnings": len(gate.by_verdict(WARNING)),
        "tests": [asdict(result) for result in gate.tests],
    }


def _policy_changes(previous_policy: Path, check: PolicyCheck) -> list[str]:
    if not previous_policy.exists():
        return ["initial deployment: no previously deployed policy"]
    result = diff_policies(compile_path(previous_policy), check.ir)
    lines = [f"+ {c.name} added" for c in result.added]
    lines += [f"- {c.name} removed" for c in result.removed]
    lines += [f"~ {c.name}: {'; '.join(c.notes)}" for c in result.modified]
    lines.append(f"security impact: {result.risk}")
    return lines


def _check_and_render(
    policy: Path,
    target: str,
    *,
    baseline: Path | None,
    environment: str | None,
    fail_on: str | None,
    native_syntax: bool,
    today: date | None,
) -> tuple[PolicyCheck, RenderedConfig]:
    check = check_path(
        policy, fail_on=fail_on, baseline=baseline, environment=environment, today=today
    )
    try:
        rendered = render_config(check.ir, target, native_syntax=native_syntax)
    except KeyError as exc:
        raise ReleaseError(str(exc)) from exc
    return check, rendered


def _blockers(check: PolicyCheck, rendered: RenderedConfig, allow_lossy: bool) -> list[str]:
    reasons = [f"gate: {item.finding.title}" for item in check.gate.by_verdict(VIOLATION)]
    if not check.controls.target_allowed(rendered.exporter.name):
        reasons.append(
            f"target {rendered.exporter.name} is not approved for "
            f"{check.controls.environment or 'this environment'}"
        )
    reasons += [f"{c.kind}: {c.detail}" for c in rendered.checks if not c.passed]
    if rendered.lossy and not allow_lossy:
        reasons += [f"lossy: {warning}" for warning in rendered.lossy]
    return reasons


def create_plan(
    policy: Path,
    target: str,
    *,
    author: str,
    baseline: Path | None = None,
    environment: str | None = None,
    fail_on: str | None = None,
    allow_lossy: bool = False,
    native_syntax: bool = False,
    state: StatePaths | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    state = state or StatePaths(DEFAULT_STATE_DIR)
    check, rendered = _check_and_render(
        policy,
        target,
        baseline=baseline,
        environment=environment,
        fail_on=fail_on,
        native_syntax=native_syntax,
        today=today,
    )
    env = check.controls.environment
    reasons = _blockers(check, rendered, allow_lossy)

    previous_config = state.deployed_config(env, target)
    before = previous_config.read_text(encoding="utf-8") if previous_config.exists() else ""
    config_diff = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            (rendered.text + "\n").splitlines(keepends=True),
            fromfile=f"deployed/{target}" if before else "/dev/null",
            tofile=f"planned/{target}",
        )
    )
    content: dict[str, Any] = {
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "author": author,
        "environment": env,
        "target": target,
        "policy": {"path": str(policy), "sha256": sha256_file(policy)},
        "baseline": (
            {"path": check.controls.source, "sha256": check.controls.baseline_sha256}
            if check.controls.baseline_sha256
            else None
        ),
        "fail_on": fail_on,
        "allow_lossy": allow_lossy,
        "native_syntax": native_syntax,
        "required_approvals": check.controls.required_approvals,
        "sign_approvals": check.controls.sign_approvals,
        "gate": _gate_summary(check),
        "verification": [asdict(c) for c in rendered.checks],
        "lossy": list(rendered.lossy),
        "deployable": not reasons,
        "blockers": reasons,
        "policy_changes": _policy_changes(state.deployed_policy(env, target), check),
        "config_diff": config_diff,
        "config": {"sha256": rendered.sha256, "text": rendered.text},
    }
    plan = {"format": PLAN_FORMAT, "plan_id": plan_id(content), "content": content,
            "approvals": []}
    append_event(
        state.audit_log,
        "plan",
        author,
        plan_id=plan["plan_id"],
        environment=env,
        target=target,
        policy_sha256=content["policy"]["sha256"],
        config_sha256=rendered.sha256,
        deployable=not reasons,
    )
    return plan


def load_plan(path: Path) -> dict[str, Any]:
    try:
        plan: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot read plan {path}: {exc}") from exc
    if plan.get("format") != PLAN_FORMAT:
        raise ReleaseError(f"{path} is not a {PLAN_FORMAT} file")
    if plan_id(plan["content"]) != plan.get("plan_id"):
        raise ReleaseError(f"{path} was modified after it was created (plan_id mismatch)")
    return plan


def save_plan(plan: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")


def approve_plan(
    plan: dict[str, Any],
    approver: str,
    *,
    comment: str = "",
    state: StatePaths | None = None,
) -> dict[str, Any]:
    state = state or StatePaths(DEFAULT_STATE_DIR)
    content = plan["content"]
    if not approver.strip():
        raise ReleaseError("an approver identity is required")
    if approver == content["author"]:
        raise ReleaseError("the author of a plan cannot approve it")
    if not content["deployable"]:
        raise ReleaseError("plan is not deployable", tuple(content["blockers"]))
    if any(a["by"] == approver for a in plan["approvals"]):
        raise ReleaseError(f"{approver} has already approved this plan")
    if content["sign_approvals"] and not os.environ.get(APPROVAL_KEY_VAR):
        raise ReleaseError(f"this environment requires signed approvals; set {APPROVAL_KEY_VAR}")
    approval = {
        "by": approver,
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "comment": comment,
        "signature": _sign(plan["plan_id"], approver),
    }
    plan["approvals"].append(approval)
    append_event(
        state.audit_log,
        "approve",
        approver,
        plan_id=plan["plan_id"],
        environment=content["environment"],
        target=content["target"],
        comment=comment,
        signed=bool(approval["signature"]),
    )
    return plan


def valid_approvers(plan: dict[str, Any]) -> list[str]:
    """Distinct approvers that count toward the quorum."""

    content = plan["content"]
    counted: list[str] = []
    for approval in plan["approvals"]:
        approver = approval.get("by", "")
        if not approver or approver == content["author"] or approver in counted:
            continue
        if content["sign_approvals"]:
            expected = _sign(plan["plan_id"], approver)
            if not expected or not hmac.compare_digest(expected, approval.get("signature", "")):
                continue
        counted.append(approver)
    return counted


def _command_line(command: str, config: Path) -> str | list[str]:
    """Substitute ``{config}`` without invoking a shell.

    POSIX commands are split with shlex; on Windows the command line is passed to
    CreateProcess as-is, because shlex would strip the backslashes in paths.
    """

    if os.name == "nt":
        return command.replace("{config}", subprocess.list2cmdline([str(config)]))
    return [part.replace("{config}", str(config)) for part in shlex.split(command)]


@dataclass(frozen=True, slots=True)
class DeployResult:
    plan_id: str
    destination: Path | None
    approvers: tuple[str, ...]
    command_output: str = ""
    dry_run: bool = False


def _verify_for_deploy(plan: dict[str, Any], today: date | None) -> list[str]:
    content = plan["content"]
    policy = Path(content["policy"]["path"])
    baseline = Path(content["baseline"]["path"]) if content["baseline"] else None
    reasons: list[str] = []
    if not policy.is_file():
        return [f"policy file {policy} is missing"]
    if sha256_file(policy) != content["policy"]["sha256"]:
        reasons.append("policy changed since the plan was approved")
    if baseline is not None and (
        not baseline.is_file() or sha256_file(baseline) != content["baseline"]["sha256"]
    ):
        reasons.append("baseline changed since the plan was approved")
    if reasons:
        return reasons

    check, rendered = _check_and_render(
        policy,
        content["target"],
        baseline=baseline,
        environment=content["environment"] or None,
        fail_on=content["fail_on"],
        native_syntax=content["native_syntax"],
        today=today,
    )
    reasons += _blockers(check, rendered, content["allow_lossy"])
    if rendered.sha256 != content["config"]["sha256"]:
        reasons.append("regenerated configuration differs from the approved plan")

    approvers = valid_approvers(plan)
    required = check.controls.required_approvals
    if len(approvers) < required:
        reasons.append(
            f"{len(approvers)} of {required} required approval(s) "
            f"for {check.controls.environment or 'this environment'}"
        )
    return reasons


def deploy_plan(
    plan: dict[str, Any],
    *,
    actor: str,
    destination: Path | None = None,
    command: str | None = None,
    dry_run: bool = False,
    state: StatePaths | None = None,
    today: date | None = None,
) -> DeployResult:
    state = state or StatePaths(DEFAULT_STATE_DIR)
    content = plan["content"]
    env, target = content["environment"], content["target"]
    audit = {"plan_id": plan["plan_id"], "environment": env, "target": target}

    reasons = _verify_for_deploy(plan, today)
    if destination is None and command is None and not dry_run:
        reasons.append("nothing to deploy to: pass --to and/or --run")
    if reasons:
        append_event(state.audit_log, "deploy_refused", actor, **audit, reasons=reasons)
        raise ReleaseError("deployment refused", tuple(reasons))

    approvers = tuple(valid_approvers(plan))
    if dry_run:
        return DeployResult(plan["plan_id"], destination, approvers, dry_run=True)

    text = content["config"]["text"] + "\n"
    staged = state.root / "staging" / f"{plan['plan_id'][:12]}-{target}.cfg"
    staged.parent.mkdir(parents=True, exist_ok=True)
    staged.write_text(text, encoding="utf-8")
    config_path = staged
    if destination is not None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".py2fw-tmp")
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, destination)
        config_path = destination

    output = ""
    if command is not None:
        proc = subprocess.run(
            _command_line(command, config_path), capture_output=True, text=True, check=False
        )
        output = (proc.stdout + proc.stderr).strip()
        if proc.returncode != 0:
            append_event(
                state.audit_log,
                "deploy_failed",
                actor,
                **audit,
                command=command,
                exit_code=proc.returncode,
                output=output[-2000:],
            )
            raise ReleaseError(
                f"deploy command exited with {proc.returncode}", (output[-2000:],)
            )

    deployed = state.deployed_config(env, target)
    deployed.parent.mkdir(parents=True, exist_ok=True)
    deployed.write_text(text, encoding="utf-8")
    shutil.copyfile(content["policy"]["path"], state.deployed_policy(env, target))
    append_event(
        state.audit_log,
        "deploy",
        actor,
        **audit,
        author=content["author"],
        approvers=list(approvers),
        policy_sha256=content["policy"]["sha256"],
        config_sha256=content["config"]["sha256"],
        destination=str(destination) if destination else None,
        command=command,
    )
    return DeployResult(plan["plan_id"], destination, approvers, output)
