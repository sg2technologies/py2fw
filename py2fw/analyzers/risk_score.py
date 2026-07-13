from __future__ import annotations

from py2fw.analyzers.models import Finding

WEIGHTS: dict[str, int] = {"high": 25, "medium": 10, "low": 3}


def calculate_risk_score(findings: list[Finding]) -> int:
    return min(100, sum(WEIGHTS.get(finding.severity, 0) for finding in findings))
