from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str
    title: str
    rule: str | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    risk_score: int
    findings: tuple[Finding, ...]

    def by_severity(self, severity: str) -> tuple[Finding, ...]:
        return tuple(finding for finding in self.findings if finding.severity == severity)
