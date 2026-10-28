from __future__ import annotations

from datetime import date
from pathlib import Path

from py2fw.analyzers.engine import analyze_ir
from py2fw.analyzers.gate import DEFAULT_FAIL_ON, GateReport, evaluate_gate
from py2fw.compiler.builder import build_ir
from py2fw.compiler.hosts import HostResolution, resolve_document_hosts
from py2fw.compiler.ir import FirewallIR
from py2fw.compiler.optimizer import optimize_ir
from py2fw.compiler.validator import ValidationResult, validate_document
from py2fw.parser.schema import PolicyDocument
from py2fw.parser.source_map import SourceMap
from py2fw.parser.yaml_parser import parse_policy_with_source


class CompileError(ValueError):
    """Raised when a valid-YAML policy fails semantic validation."""


def load_document(path: Path) -> tuple[PolicyDocument, SourceMap]:
    return parse_policy_with_source(path)


def validate_path(path: Path) -> tuple[PolicyDocument, ValidationResult]:
    document, source = load_document(path)
    return document, validate_document(document, source)


def compile_path(
    path: Path, *, resolve_hosts: bool = False, refresh_hosts: bool = False
) -> FirewallIR:
    ir, _ = _compile_validated(path, resolve_hosts=resolve_hosts, refresh_hosts=refresh_hosts)
    return ir


def check_path(
    path: Path,
    *,
    fail_on: str = DEFAULT_FAIL_ON,
    resolve_hosts: bool = False,
    refresh_hosts: bool = False,
    today: date | None = None,
) -> tuple[FirewallIR, GateReport]:
    """Compile, analyze and gate a policy; the IR is only safe to export if the gate passed."""

    ir, validation = _compile_validated(
        path, resolve_hosts=resolve_hosts, refresh_hosts=refresh_hosts
    )
    gate = evaluate_gate(ir, analyze_ir(ir), validation, fail_on=fail_on, today=today)
    return ir, gate


def _compile_validated(
    path: Path, *, resolve_hosts: bool, refresh_hosts: bool
) -> tuple[FirewallIR, ValidationResult]:
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
    return optimize_ir(build_ir(document, source, host_map=hosts.mapping)), validation
