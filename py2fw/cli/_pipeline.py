from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from py2fw.analyzers.engine import analyze_ir
from py2fw.analyzers.gate import GateReport, evaluate_gate
from py2fw.analyzers.models import AnalysisReport
from py2fw.analyzers.risk_score import calculate_risk_score
from py2fw.compiler.builder import build_ir
from py2fw.compiler.hosts import HostResolution, resolve_document_hosts
from py2fw.compiler.ir import FirewallIR
from py2fw.compiler.optimizer import optimize_ir
from py2fw.compiler.validator import ValidationResult, validate_document
from py2fw.enforcement.baseline import (
    BaselineError,
    Controls,
    enforce_baseline,
    load_baseline,
    resolve_controls,
)
from py2fw.exporters._helpers import describe_lossiness
from py2fw.parser.schema import PolicyDocument
from py2fw.parser.source_map import SourceMap
from py2fw.parser.yaml_parser import parse_policy_with_source
from py2fw.plugins.base import Exporter
from py2fw.plugins.registry import load_builtin_exporters
from py2fw.verify.config import ConfigCheck, check_intent, check_syntax
from py2fw.verify.regression import run_flow_tests

BASELINE_ENV_VAR = "PY2FW_BASELINE"


class CompileError(ValueError):
    """Raised when a valid-YAML policy fails semantic validation."""


@dataclass(frozen=True, slots=True)
class PolicyCheck:
    """Everything the gate decided about one policy, plus the IR it decided on."""

    ir: FirewallIR
    document: PolicyDocument
    controls: Controls
    report: AnalysisReport
    gate: GateReport


@dataclass(frozen=True, slots=True)
class RenderedConfig:
    """A generated vendor configuration and the checks run against it."""

    exporter: Exporter
    text: str
    lossy: tuple[str, ...]
    checks: tuple[ConfigCheck, ...]

    @property
    def verified(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


def render_config(ir: FirewallIR, target: str, *, native_syntax: bool = False) -> RenderedConfig:
    """Export ``ir`` for ``target`` and validate the result (raises KeyError on unknown target)."""

    exporter = load_builtin_exporters().create(target)
    text = exporter.export(ir)
    checks = (
        *check_syntax(exporter, text, native=native_syntax),
        check_intent(ir, exporter, text),
    )
    return RenderedConfig(
        exporter=exporter,
        text=text,
        lossy=tuple(describe_lossiness(ir, exporter.capabilities)),
        checks=checks,
    )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_document(path: Path) -> tuple[PolicyDocument, SourceMap]:
    return parse_policy_with_source(path)


def validate_path(path: Path) -> tuple[PolicyDocument, ValidationResult]:
    document, source = load_document(path)
    return document, validate_document(document, source)


def compile_path(
    path: Path, *, resolve_hosts: bool = False, refresh_hosts: bool = False
) -> FirewallIR:
    _, ir, _ = _compile_validated(path, resolve_hosts=resolve_hosts, refresh_hosts=refresh_hosts)
    return ir


def load_controls(
    baseline: Path | None, environment: str | None, document: PolicyDocument
) -> Controls:
    """Resolve the controls for this policy's environment.

    The baseline comes from ``baseline`` or the ``PY2FW_BASELINE`` variable. The
    environment comes from ``environment`` or the policy's ``environment:`` field;
    if both are given they must agree, so a prod policy can't be checked as dev.
    """

    declared = document.environment
    if environment and declared and environment != declared:
        raise BaselineError(
            f"--env {environment} does not match the policy's environment '{declared}'"
        )
    env = environment or declared
    if baseline is None and os.environ.get(BASELINE_ENV_VAR):
        baseline = Path(os.environ[BASELINE_ENV_VAR])
    if baseline is None:
        return resolve_controls(None, env)
    if not baseline.is_file():
        raise BaselineError(f"baseline not found: {baseline}")
    return resolve_controls(
        load_baseline(baseline), env, baseline_sha256=sha256_file(baseline), source=str(baseline)
    )


def check_path(
    path: Path,
    *,
    fail_on: str | None = None,
    baseline: Path | None = None,
    environment: str | None = None,
    resolve_hosts: bool = False,
    refresh_hosts: bool = False,
    today: date | None = None,
) -> PolicyCheck:
    """Compile, analyze, enforce the baseline, run regression tests and gate a policy.

    The IR is only safe to export if ``gate.passed``.
    """

    document, ir, validation = _compile_validated(
        path, resolve_hosts=resolve_hosts, refresh_hosts=refresh_hosts
    )
    controls = load_controls(baseline, environment, document)
    findings = [*analyze_ir(ir).findings, *enforce_baseline(ir, controls)]
    report = AnalysisReport(risk_score=calculate_risk_score(findings), findings=tuple(findings))
    tests = [
        *run_flow_tests(ir, document.tests, "policy"),
        *run_flow_tests(ir, controls.tests, "baseline"),
    ]
    gate = evaluate_gate(
        ir, report, validation, fail_on=fail_on, controls=controls, tests=tests, today=today
    )
    return PolicyCheck(ir=ir, document=document, controls=controls, report=report, gate=gate)


def _compile_validated(
    path: Path, *, resolve_hosts: bool, refresh_hosts: bool
) -> tuple[PolicyDocument, FirewallIR, ValidationResult]:
    document, source = load_document(path)
    validation = validate_document(document, source)
    if not validation.ok:
        messages = "; ".join(
            f"{issue.location}: {issue.message}"
            for issue in validation.issues
            if issue.severity == "error"
        )
        raise CompileError(f"policy validation failed: {messages}")

    hosts: HostResolution = resolve_document_hosts(
        document, path, do_dns=resolve_hosts, refresh=refresh_hosts
    )
    ir = optimize_ir(build_ir(document, source, host_map=hosts.mapping))
    return document, ir, validation
