"""Map policy structure to security-control frameworks.

These are heuristic mappings from what Py2FW can see in a compiled policy
(sources, destinations, services, actions, default-deny semantics) to specific
controls in PCI DSS, NIST SP 800-53 and the CIS Controls. A ``pass`` means the
policy demonstrably supports the control; ``review`` means the control depends
on information Py2FW does not model (zones, logging, physical topology);
``fail`` means the policy actively contradicts the control.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from py2fw.analyzers.models import Finding
from py2fw.compiler.ir import FirewallIR, PolicyIR
from py2fw.compiler.query import address_values, service_values
from py2fw.utils.constants import BROAD_PREFIX_MAX_LEN, DATABASE_PORTS, HIGH_RISK_PORTS

PASS = "pass"
REVIEW = "review"
FAIL = "fail"

FRAMEWORKS = ("pci", "nist", "cis")
_FRAMEWORK_TITLES = {
    "pci": "PCI DSS v4.0",
    "nist": "NIST SP 800-53 Rev 5",
    "cis": "CIS Controls v8",
}


@dataclass(frozen=True, slots=True)
class ControlResult:
    framework: str
    control: str
    title: str
    status: str
    detail: str
    rules: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ComplianceReport:
    results: tuple[ControlResult, ...]

    def by_status(self, status: str) -> tuple[ControlResult, ...]:
        return tuple(r for r in self.results if r.status == status)

    def for_framework(self, framework: str) -> tuple[ControlResult, ...]:
        return tuple(r for r in self.results if r.framework == framework)


# --- structural facts about the policy -------------------------------------


@dataclass(frozen=True, slots=True)
class _Facts:
    any_to_any: tuple[str, ...]
    untrusted_all_ports: tuple[str, ...]
    untrusted_wide_range: tuple[str, ...]
    internet_to_database: tuple[str, ...]
    segmentation_rules: tuple[str, ...]
    explicit_rules: bool

    @property
    def excessive_exposure(self) -> tuple[str, ...]:
        return tuple(sorted({*self.untrusted_all_ports, *self.untrusted_wide_range}))


def _is_broad_source(values: tuple[str, ...]) -> bool:
    for value in values:
        if value == "any":
            return True
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if not net.is_private and net.prefixlen <= BROAD_PREFIX_MAX_LEN[net.version]:
            return True
    return False


def _rule_port_profile(ir: FirewallIR, rule: PolicyIR) -> tuple[bool, set[int], int]:
    all_ports = False
    sensitive: set[int] = set()
    widest = 0
    watch = frozenset(DATABASE_PORTS | set(HIGH_RISK_PORTS))
    for svc in service_values(ir, rule.services):
        if svc.ports.is_all_ports or svc.protocol == "any":
            all_ports = True
        sensitive |= svc.ports.matching(watch)
        for prange in svc.ports.ranges:
            widest = max(widest, prange.end - prange.start)
    return all_ports, sensitive, widest


def _facts(ir: FirewallIR) -> _Facts:
    any_to_any: list[str] = []
    all_ports: list[str] = []
    wide_range: list[str] = []
    to_db: list[str] = []
    segmentation: list[str] = []
    explicit = True

    for rule in ir.policies:
        if not (rule.source and rule.destination and rule.services):
            explicit = False
        if rule.action != "allow" or not rule.enabled:
            continue
        dst = address_values(ir, rule.destination)
        broad = _is_broad_source(address_values(ir, rule.source))
        rule_all_ports, sensitive, widest = _rule_port_profile(ir, rule)

        if broad and "any" in dst:
            any_to_any.append(rule.name)
        if broad and rule_all_ports:
            all_ports.append(rule.name)
        if broad and widest >= 1024:
            wide_range.append(rule.name)
        if broad and sensitive & set(DATABASE_PORTS):
            to_db.append(rule.name)
        if not broad and "any" not in dst and not rule_all_ports:
            segmentation.append(rule.name)

    return _Facts(
        any_to_any=tuple(any_to_any),
        untrusted_all_ports=tuple(all_ports),
        untrusted_wide_range=tuple(wide_range),
        internet_to_database=tuple(to_db),
        segmentation_rules=tuple(segmentation),
        explicit_rules=explicit,
    )


# --- control catalogue ----------------------------------------------------
#
# Each entry: (framework, control, title, facts-attribute, ok-detail, fail-detail).
# A non-empty list on the named attribute means the control fails.

_FAIL_ON_RULES: tuple[tuple[str, str, str, str, str, str], ...] = (
    (
        "pci", "1.2.1", "NSC rulesets restrict traffic to that which is necessary",
        "untrusted_all_ports",
        "Rules from untrusted sources are restricted to specific services.",
        "Untrusted source permitted to all ports",
    ),
    (
        "pci", "1.2.5", "Only necessary ports, protocols and services are allowed",
        "untrusted_wide_range",
        "No broad port ranges are opened to untrusted sources.",
        "Wide port range opened to an untrusted source",
    ),
    (
        "pci", "1.4.1", "NSCs are implemented between trusted and untrusted networks",
        "any_to_any",
        "Default-deny is enforced and no permit-any-any rule exists.",
        "Permit any-to-any rule defeats the boundary control",
    ),
    (
        "pci", "1.4.4",
        "Stored-cardholder-data components are not directly reachable from untrusted networks",
        "internet_to_database",
        "No rule exposes a database port to an untrusted source.",
        "Database port reachable from an untrusted network",
    ),
    (
        "nist", "SC-7", "Boundary Protection",
        "any_to_any",
        "Boundary protection with deny-by-default is in effect.",
        "any-to-any allow rule weakens boundary protection",
    ),
    (
        "nist", "CM-7", "Least Functionality",
        "excessive_exposure",
        "Services exposed to untrusted sources are narrowly scoped.",
        "Excessive services/ports exposed to untrusted sources",
    ),
    (
        "cis", "4.4", "Implement and Manage a Firewall on Servers",
        "any_to_any",
        "Traffic filtering with an explicit default-deny is defined.",
        "any-to-any allow rule present",
    ),
)

_STATIC: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "pci", "1.3.2", "Outbound traffic from the CDE is restricted", REVIEW,
        "Py2FW does not model traffic direction or zones; review egress rules manually.",
    ),
    (
        "nist", "SC-7(5)", "Deny by Default / Allow by Exception", PASS,
        "Policy evaluation applies an implicit default-deny after the last rule.",
    ),
    (
        "nist", "AU-2 / SI-4", "Event Logging / System Monitoring", REVIEW,
        "Rule-level logging is not modeled; confirm logging on the target device.",
    ),
    (
        "cis", "12.2", "Establish and Maintain a Secure Network Architecture", REVIEW,
        "Architecture review (zones, DMZ placement) is outside Py2FW's policy model.",
    ),
)


def _catalogue(facts: _Facts) -> list[ControlResult]:
    out: list[ControlResult] = []
    for framework, control, title, attr, ok_detail, fail_detail in _FAIL_ON_RULES:
        rules: tuple[str, ...] = getattr(facts, attr)
        if rules:
            out.append(
                ControlResult(
                    framework, control, title, FAIL,
                    f"{fail_detail}: {', '.join(rules)}", rules,
                )
            )
        else:
            out.append(ControlResult(framework, control, title, PASS, ok_detail))

    for framework, control, title, status, detail in _STATIC:
        out.append(ControlResult(framework, control, title, status, detail))

    ac4_status = PASS if facts.explicit_rules else REVIEW
    ac4_detail = (
        "Every rule names an explicit source, destination and service."
        if facts.explicit_rules
        else "Some rules omit source, destination or service."
    )
    out.append(
        ControlResult("nist", "AC-4", "Information Flow Enforcement", ac4_status, ac4_detail)
    )

    if facts.segmentation_rules:
        out.append(
            ControlResult(
                "cis", "13.4", "Perform Traffic Filtering Between Network Segments", PASS,
                f"{len(facts.segmentation_rules)} scoped segment-to-segment rule(s) defined.",
                facts.segmentation_rules,
            )
        )
    else:
        out.append(
            ControlResult(
                "cis", "13.4", "Perform Traffic Filtering Between Network Segments", REVIEW,
                "No specific segment-to-segment rules detected.",
            )
        )
    return out


def compliance_report(ir: FirewallIR, frameworks: Iterable[str] = FRAMEWORKS) -> ComplianceReport:
    selected = set(frameworks)
    results = tuple(r for r in _catalogue(_facts(ir)) if r.framework in selected)
    return ComplianceReport(results=results)


def framework_title(name: str) -> str:
    return _FRAMEWORK_TITLES.get(name, name.upper())


def find_compliance_gaps(ir: FirewallIR) -> list[Finding]:
    """Feed failing controls into the ``analyze`` findings stream."""

    findings: list[Finding] = []
    for result in compliance_report(ir).results:
        if result.status != FAIL:
            continue
        findings.append(
            Finding(
                severity="high",
                title=f"Compliance gap: {framework_title(result.framework)} {result.control}",
                rule=result.rules[0] if result.rules else None,
                detail=f"{result.title} - {result.detail}",
            )
        )
    return findings
