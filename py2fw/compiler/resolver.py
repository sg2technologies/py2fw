from __future__ import annotations

from collections.abc import Mapping

from py2fw.parser.schema import PolicyDocument
from py2fw.utils.ip import normalize_network


class ResolutionError(ValueError):
    """Raised when references cannot be resolved."""


def resolve_group(
    name: str,
    objects: Mapping[str, list[str]],
    groups: Mapping[str, list[str]],
    stack: tuple[str, ...] = (),
) -> tuple[str, ...]:
    if name in objects:
        return tuple(normalize_network(value) for value in objects[name])
    if name == "any":
        return ("any",)
    if name not in groups:
        raise ResolutionError(f"unknown object or group: {name}")
    if name in stack:
        cycle = " -> ".join((*stack, name))
        raise ResolutionError(f"circular group reference: {cycle}")

    resolved: list[str] = []
    for member in groups[name]:
        resolved.extend(resolve_group(member, objects, groups, (*stack, name)))
    return tuple(dict.fromkeys(resolved))


def resolve_rule_references(document: PolicyDocument) -> dict[str, tuple[str, ...]]:
    resolved: dict[str, tuple[str, ...]] = {}
    for name in document.objects:
        resolved[name] = resolve_group(name, document.objects, document.groups)
    for name in document.groups:
        resolved[name] = resolve_group(name, document.objects, document.groups)
    resolved["any"] = ("any",)
    return resolved
