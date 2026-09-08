from __future__ import annotations

from pathlib import Path

from py2fw.compiler.builder import build_ir
from py2fw.compiler.ir import FirewallIR
from py2fw.compiler.optimizer import optimize_ir
from py2fw.compiler.validator import ValidationResult, validate_document
from py2fw.parser.schema import PolicyDocument
from py2fw.parser.yaml_parser import parse_policy


class CompileError(ValueError):
    """Raised when a valid-YAML policy fails semantic validation."""


def load_document(path: Path) -> PolicyDocument:
    return parse_policy(path)


def validate_path(path: Path) -> tuple[PolicyDocument, ValidationResult]:
    document = load_document(path)
    return document, validate_document(document)


def compile_path(path: Path) -> FirewallIR:
    document, validation = validate_path(path)
    if not validation.ok:
        messages = "; ".join(
            f"{issue.location}: {issue.message}"
            for issue in validation.issues
            if issue.severity == "error"
        )
        raise CompileError(f"policy validation failed: {messages}")
    return optimize_ir(build_ir(document))
