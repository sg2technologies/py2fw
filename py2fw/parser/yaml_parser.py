from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from py2fw.parser.schema import PolicyDocument
from py2fw.parser.source_map import SourceMap, build_source_map


class ParseError(ValueError):
    """Raised when a policy document cannot be parsed or is schema-invalid."""


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of silently keeping the last.

    A duplicated object or service name would otherwise let a reviewer read one value
    while the compiler uses another.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: dict[Any, int] = {}
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            line = key_node.start_mark.line + 1
            if key in seen:
                raise ParseError(
                    f"duplicate key '{key}' at line {line} (first defined at line {seen[key]})"
                )
            seen[key] = line
        return super().construct_mapping(node, deep=deep)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ParseError(f"cannot read policy file: {path}") from exc


def _parse_mapping(text: str) -> dict[str, Any]:
    try:
        data = yaml.load(text, Loader=_StrictLoader) or {}
    except yaml.YAMLError as exc:
        raise ParseError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError("policy root must be a YAML mapping")
    return data


def load_yaml(path: Path) -> dict[str, Any]:
    return _parse_mapping(_read(path))


def _location(loc: tuple[int | str, ...]) -> str:
    """Convert a pydantic error ``loc`` into a source-map location like ``policies[0].action``."""

    out = ""
    for part in loc:
        out += f"[{part}]" if isinstance(part, int) else (f".{part}" if out else str(part))
    return out


def _validate(data: dict[str, Any], source: SourceMap | None = None) -> PolicyDocument:
    source = source or SourceMap()
    try:
        return PolicyDocument.model_validate(data)
    except ValidationError as exc:
        details = []
        for err in exc.errors():
            location = _location(err["loc"])
            line = source.line(location) if location else None
            where = f"{location} (line {line})" if line is not None else location
            details.append(f"{where}: {err['msg']}")
        raise ParseError(f"policy schema error: {'; '.join(details)}") from exc


def parse_policy(path: Path) -> PolicyDocument:
    return _validate(load_yaml(path))


def parse_policy_with_source(path: Path) -> tuple[PolicyDocument, SourceMap]:
    text = _read(path)
    data = _parse_mapping(text)
    source = build_source_map(text, path)
    return _validate(data, source), source
