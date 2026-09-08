from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from py2fw.compiler.ir import PolicyIR


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str
    title: str
    rule: str | None = None
    detail: str = ""
    line: int | None = None
    location: str = ""


def rule_finding(rule: PolicyIR, severity: str, title: str, detail: str = "") -> Finding:
    return Finding(
        severity=severity,
        title=title,
        rule=rule.name,
        detail=detail,
        line=rule.line,
        location=rule.location,
    )


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    risk_score: int
    findings: tuple[Finding, ...]

    def by_severity(self, severity: str) -> tuple[Finding, ...]:
        return tuple(finding for finding in self.findings if finding.severity == severity)
