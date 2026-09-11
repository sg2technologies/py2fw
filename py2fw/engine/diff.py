from __future__ import annotations

from dataclasses import dataclass

from py2fw.compiler.ir import FirewallIR, PolicyIR
from py2fw.compiler.query import address_values, service_values


@dataclass(frozen=True, slots=True)
class RuleSignature:
    source: frozenset[str]
    destination: frozenset[str]
    services: frozenset[tuple[str, tuple[tuple[int, int], ...]]]
    action: str
    enabled: bool


@dataclass(frozen=True, slots=True)
class RuleChange:
    kind: str  # "added" | "removed" | "modified"
    name: str
    before: RuleSignature | None
    after: RuleSignature | None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyDiff:
    changes: tuple[RuleChange, ...]

    @property
    def added(self) -> tuple[RuleChange, ...]:
        return tuple(c for c in self.changes if c.kind == "added")

    @property
    def removed(self) -> tuple[RuleChange, ...]:
        return tuple(c for c in self.changes if c.kind == "removed")

    @property
    def modified(self) -> tuple[RuleChange, ...]:
        return tuple(c for c in self.changes if c.kind == "modified")

    @property
    def risk(self) -> str:
        return _risk(self)


def _signature(ir: FirewallIR, rule: PolicyIR) -> RuleSignature:
    services = frozenset(
        (svc.protocol, tuple((r.start, r.end) for r in svc.ports.ranges))
        for svc in service_values(ir, rule.services)
    )
    return RuleSignature(
        source=frozenset(address_values(ir, rule.source)),
        destination=frozenset(address_values(ir, rule.destination)),
        services=services,
        action=rule.action,
        enabled=rule.enabled,
    )


def _describe(before: RuleSignature, after: RuleSignature) -> tuple[str, ...]:
    notes: list[str] = []
    if before.action != after.action:
        notes.append(f"action {before.action} -> {after.action}")
    if before.enabled != after.enabled:
        notes.append("enabled -> disabled" if before.enabled else "disabled -> enabled")
    if before.source != after.source:
        notes.append(f"source {_fmt(before.source)} -> {_fmt(after.source)}")
        if after.source > before.source or "any" in after.source:
            notes.append("source scope broadened")
    if before.destination != after.destination:
        notes.append(f"destination {_fmt(before.destination)} -> {_fmt(after.destination)}")
    if before.services != after.services:
        notes.append("service set changed")
    return tuple(notes)


def _fmt(values: frozenset[str]) -> str:
    return "{" + ", ".join(sorted(values)) + "}"


def diff_policies(old: FirewallIR, new: FirewallIR) -> PolicyDiff:
    old_rules = {rule.name: rule for rule in old.policies}
    new_rules = {rule.name: rule for rule in new.policies}
    changes: list[RuleChange] = []

    for name, rule in new_rules.items():
        if name not in old_rules:
            changes.append(RuleChange("added", name, None, _signature(new, rule)))
            continue
        before = _signature(old, old_rules[name])
        after = _signature(new, rule)
        if before != after:
            changes.append(RuleChange("modified", name, before, after, _describe(before, after)))

    for name, rule in old_rules.items():
        if name not in new_rules:
            changes.append(RuleChange("removed", name, _signature(old, rule), None))

    return PolicyDiff(changes=tuple(changes))


def _risk(diff: PolicyDiff) -> str:
    score = 0
    for change in diff.changes:
        if change.kind == "added" and change.after and change.after.action == "allow":
            score += 2
        removed_block = change.before and change.before.action in ("deny", "reject")
        if change.kind == "removed" and removed_block:
            score += 3
        if change.kind == "removed" and change.before and change.before.action == "allow":
            score += 1
        if change.kind == "modified" and "source scope broadened" in change.notes:
            score += 2
        if change.kind == "modified" and any(n.startswith("action") for n in change.notes):
            score += 1
    if score >= 5:
        return "HIGH"
    if score >= 2:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
