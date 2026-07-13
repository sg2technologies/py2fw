from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from py2fw.parser.schema import PolicyDocument


class ParseError(ValueError):
    """Raised when a policy document cannot be parsed."""


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise ParseError(f"cannot read policy file: {path}") from exc
    except yaml.YAMLError as exc:
        raise ParseError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError("policy root must be a YAML mapping")
    return data


def parse_policy(path: Path) -> PolicyDocument:
    return PolicyDocument.model_validate(load_yaml(path))
