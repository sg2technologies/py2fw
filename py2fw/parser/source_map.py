"""Map logical policy locations (``policies[0].source``) back to YAML line numbers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_INDEX_OR_FIELD = re.compile(r"(\[\d+\]|\.[^.\[]+)$")


@dataclass(frozen=True, slots=True)
class SourceMap:
    """Lookup from a dotted/indexed location string to a 1-indexed source line."""

    lines: dict[str, int] = field(default_factory=dict)
    path: Path | None = None

    def line(self, location: str) -> int | None:
        probe = location
        while probe:
            if probe in self.lines:
                return self.lines[probe]
            trimmed = _INDEX_OR_FIELD.sub("", probe)
            if trimmed == probe:
                return None
            probe = trimmed
        return None

    def ref(self, location: str) -> str:
        found = self.line(location)
        if found is None:
            return location
        name = self.path.name if self.path is not None else "policy"
        return f"{name}:{found} ({location})"


def _walk(node: yaml.Node, prefix: str, out: dict[str, int]) -> None:
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            key = str(key_node.value)
            location = f"{prefix}.{key}" if prefix else key
            out[location] = key_node.start_mark.line + 1
            _walk(value_node, location, out)
    elif isinstance(node, yaml.SequenceNode):
        for index, item in enumerate(node.value):
            location = f"{prefix}[{index}]"
            out[location] = item.start_mark.line + 1
            _walk(item, location, out)


def build_source_map(text: str, path: Path | None = None) -> SourceMap:
    try:
        root = yaml.compose(text)
    except yaml.YAMLError:
        return SourceMap({}, path)
    out: dict[str, int] = {}
    if root is not None:
        _walk(root, "", out)
    return SourceMap(out, path)
