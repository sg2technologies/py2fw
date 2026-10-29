"""Deployment gate: classify findings as blocking violations or advisory warnings.

* **violation** - blocks ``check`` and ``compile``: a finding at or above ``fail_on``
  with no valid exception, a finding covered only by an expired, over-long or
  disallowed exception, any ``critical`` finding (critical findings cannot be
  waived), a validation error, or a failed regression test.
* **warning** - reported but never blocks: findings below ``fail_on``, validation
  warnings, and exceptions that no longer match any finding.
* **waived** - a blocking finding covered by an exception the environment accepts.

``fail_on`` and the exception rules come from the environment's
:class:`~py2fw.enforcement.baseline.Controls`. When a baseline is in force, a
``fail_on`` passed by the caller can only make the gate stricter.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date

from py2fw.analyzers.models import AnalysisReport, Finding
from py2fw.compiler.ir import ExceptionIR, FirewallIR
from py2fw.compiler.validator import ValidationResult
from py2fw.enforcement.baseline import DEFAULT_FAIL_ON, Controls
from py2fw.verify.regression import FlowTestResult

SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
UNWAIVABLE = "critical"

VIOLATION = "violation"
WARNING = "warning"
WAIVED = "waived"

__all__ = [
    "DEFAULT_FAIL_ON",
    "SEVERITY_RANK",
    "VIOLATION",
    "WAIVED",
    "WARNING",
    "GateItem",
    "GateReport",
    "effective_fail_on",
    "evaluate_gate",
]


@dataclass(frozen=True, slots=True)
class GateItem:
    verdict: str
    finding: Finding
    note: str = ""


@dataclass(frozen=True, slots=True)
class GateReport:
    fail_on: str
    items: tuple[GateItem, ...]
    environment: str = ""
    tests: tuple[FlowTestResult, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        return not self.by_verdict(VIOLATION)

    def by_verdict(self, verdict: str) -> tuple[GateItem, ...]:
        return tuple(item for item in self.items if item.verdict == verdict)


def effective_fail_on(requested: str | None, controls: Controls) -> str:
    if requested is None:
        return controls.fail_on
    if requested not in SEVERITY_RANK:
        raise ValueError(f"unknown severity: {requested}")
    if not controls.baseline_sha256:
        return requested
    return min(requested, controls.fail_on, key=SEVERITY_RANK.__getitem__)


def _classify(
    finding: Finding,
    waiver: ExceptionIR | None,
    fail_on: str,
    controls: Controls,
    today: date,
) -> GateItem:
    if SEVERITY_RANK.get(finding.severity, 0) < SEVERITY_RANK[fail_on]:
        return GateItem(WARNING, finding)
    if waiver is None:
        return GateItem(VIOLATION, finding)
    if finding.severity == UNWAIVABLE:
        return GateItem(VIOLATION, finding, "critical findings cannot be waived")
    env = controls.environment or "this environment"
    if not controls.allow_exceptions:
        return GateItem(VIOLATION, finding, f"exceptions are not permitted in {env}")
    if waiver.expires < today:
        return GateItem(VIOLATION, finding, f"exception expired on {waiver.expires}")
    limit = controls.max_exception_days
    if limit is not None and (waiver.expires - today).days > limit:
        return GateItem(
            VIOLATION, finding, f"exception runs past the {limit}-day maximum for {env}"
        )
    ticket = f" [{waiver.ticket}]" if waiver.ticket else ""
    return GateItem(WAIVED, finding, f"{waiver.reason}{ticket} (until {waiver.expires})")


def evaluate_gate(
    ir: FirewallIR,
    report: AnalysisReport,
    validation: ValidationResult | None = None,
    *,
    fail_on: str | None = None,
    controls: Controls | None = None,
    tests: Iterable[FlowTestResult] = (),
    today: date | None = None,
) -> GateReport:
    controls = controls or Controls()
    threshold = effective_fail_on(fail_on, controls)
    today = today or date.today()
    waivers = {(waiver.rule, waiver.finding): waiver for waiver in ir.exceptions}
    used: set[tuple[str, str]] = set()

    items: list[GateItem] = []
    if validation is not None:
        for issue in validation.issues:
            finding = Finding(
                severity="low" if issue.severity == "warning" else UNWAIVABLE,
                title=issue.message,
                line=issue.line,
                location=issue.location,
            )
            verdict = WARNING if issue.severity == "warning" else VIOLATION
            items.append(GateItem(verdict, finding, "validation"))

    for finding in report.findings:
        key = (finding.rule or "", finding.title)
        waiver = waivers.get(key)
        if waiver is not None:
            used.add(key)
        items.append(_classify(finding, waiver, threshold, controls, today))

    test_results = tuple(tests)
    for result in test_results:
        if not result.passed:
            failed = Finding(
                severity=UNWAIVABLE,
                title=f"Regression test failed: {result.name}",
                detail=f"{result.origin} test - {result.detail}",
                line=result.line,
                location=result.location,
            )
            items.append(GateItem(VIOLATION, failed))

    for key, waiver in waivers.items():
        if key not in used:
            stale = Finding(
                severity="low",
                title="Unused exception",
                rule=waiver.rule,
                detail=f"no '{waiver.finding}' finding on this rule; remove the exception",
                line=waiver.line,
                location=waiver.location,
            )
            items.append(GateItem(WARNING, stale))

    return GateReport(
        fail_on=threshold,
        items=tuple(items),
        environment=controls.environment,
        tests=test_results,
    )
