"""Deployment gate: classify findings as blocking violations or advisory warnings.

* **violation** - blocks ``check`` and ``compile``: a finding at or above ``fail_on``
  with no valid exception, a finding covered only by an expired exception, or any
  ``critical`` finding (critical findings cannot be waived).
* **warning** - reported but never blocks: findings below ``fail_on``, validation
  warnings, and exceptions that no longer match any finding.
* **waived** - a blocking finding covered by an unexpired exception with a reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from py2fw.analyzers.models import AnalysisReport, Finding
from py2fw.compiler.ir import ExceptionIR, FirewallIR
from py2fw.compiler.validator import ValidationResult

SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
DEFAULT_FAIL_ON = "high"
UNWAIVABLE = "critical"

VIOLATION = "violation"
WARNING = "warning"
WAIVED = "waived"


@dataclass(frozen=True, slots=True)
class GateItem:
    verdict: str
    finding: Finding
    note: str = ""


@dataclass(frozen=True, slots=True)
class GateReport:
    fail_on: str
    items: tuple[GateItem, ...]

    @property
    def passed(self) -> bool:
        return not self.by_verdict(VIOLATION)

    def by_verdict(self, verdict: str) -> tuple[GateItem, ...]:
        return tuple(item for item in self.items if item.verdict == verdict)


def _classify(
    finding: Finding, waiver: ExceptionIR | None, fail_on: str, today: date
) -> GateItem:
    if SEVERITY_RANK.get(finding.severity, 0) < SEVERITY_RANK[fail_on]:
        return GateItem(WARNING, finding)
    if waiver is None:
        return GateItem(VIOLATION, finding)
    if finding.severity == UNWAIVABLE:
        return GateItem(VIOLATION, finding, "critical findings cannot be waived")
    if waiver.expires < today:
        return GateItem(VIOLATION, finding, f"exception expired on {waiver.expires}")
    ticket = f" [{waiver.ticket}]" if waiver.ticket else ""
    return GateItem(WAIVED, finding, f"{waiver.reason}{ticket} (until {waiver.expires})")


def evaluate_gate(
    ir: FirewallIR,
    report: AnalysisReport,
    validation: ValidationResult | None = None,
    *,
    fail_on: str = DEFAULT_FAIL_ON,
    today: date | None = None,
) -> GateReport:
    if fail_on not in SEVERITY_RANK:
        raise ValueError(f"unknown severity: {fail_on}")
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
        items.append(_classify(finding, waiver, fail_on, today))

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

    return GateReport(fail_on=fail_on, items=tuple(items))
