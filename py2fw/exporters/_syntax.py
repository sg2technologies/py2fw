"""Building blocks for exporters' ``check_syntax`` implementations.

Each returns a list of human-readable problems; an empty list means the
rendered configuration is well-formed for that format.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable

import yaml


def json_document(rendered: str, required_lists: Iterable[str]) -> tuple[object, list[str]]:
    try:
        data = json.loads(rendered)
    except json.JSONDecodeError as exc:
        return None, [f"invalid JSON: {exc}"]
    if not isinstance(data, dict):
        return data, ["JSON root must be an object"]
    problems = [
        f"missing or non-list '{key}'"
        for key in required_lists
        if not isinstance(data.get(key), list)
    ]
    return data, problems


def yaml_document(rendered: str, required: dict[str, str]) -> tuple[object, list[str]]:
    try:
        data = yaml.safe_load(rendered)
    except yaml.YAMLError as exc:
        return None, [f"invalid YAML: {exc}"]
    if not isinstance(data, dict):
        return data, ["YAML root must be a mapping"]
    problems = [
        f"'{key}' must be '{value}'" for key, value in required.items() if data.get(key) != value
    ]
    return data, problems


def line_grammar(rendered: str, patterns: Iterable[str], *, skip_blank: bool = True) -> list[str]:
    """Every non-blank line must fully match one of ``patterns``."""

    compiled = [re.compile(pattern) for pattern in patterns]
    problems: list[str] = []
    for number, line in enumerate(rendered.splitlines(), start=1):
        if skip_blank and not line.strip():
            continue
        if not any(regex.fullmatch(line) for regex in compiled):
            problems.append(f"line {number}: unrecognised statement: {line.strip()}")
    return problems


def balanced_blocks(
    rendered: str, opener: re.Pattern[str], closer: re.Pattern[str], label: str
) -> list[str]:
    depth = 0
    for number, line in enumerate(rendered.splitlines(), start=1):
        if opener.match(line):
            depth += 1
        elif closer.match(line):
            depth -= 1
            if depth < 0:
                return [f"line {number}: unmatched {label} close"]
    return [f"{depth} unclosed {label} block(s)"] if depth else []


def unique(values: Iterable[object], label: str) -> list[str]:
    seen: set[object] = set()
    repeated: set[str] = set()
    for value in values:
        if value in seen:
            repeated.add(str(value))
        seen.add(value)
    duplicates = sorted(repeated)
    return [f"duplicate {label}: {', '.join(duplicates)}"] if duplicates else []
