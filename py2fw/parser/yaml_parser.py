from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from py2fw.parser.schema import PolicyDocument
from py2fw.parser.source_map import SourceMap, build_source_map


class ParseError(ValueError):
    """Raised when a policy document cannot be parsed or is schema-invalid."""


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ParseError(f"cannot read policy file: {path}") from exc


def _parse_mapping(text: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ParseError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError("policy root must be a YAML mapping")
    return data


def load_yaml(path: Path) -> dict[str, Any]:
    return _parse_mapping(_read(path))


def _validate(data: dict[str, Any]) -> PolicyDocument:
    try:
        return PolicyDocument.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        raise ParseError(f"policy schema error: {details}") from exc


def parse_policy(path: Path) -> PolicyDocument:
    return _validate(load_yaml(path))


def parse_policy_with_source(path: Path) -> tuple[PolicyDocument, SourceMap]:
    text = _read(path)
    document = _validate(_parse_mapping(text))
    return document, build_source_map(text, path)
