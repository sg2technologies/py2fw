from __future__ import annotations

import json
from dataclasses import asdict

from py2fw.analyzers.models import AnalysisReport


def render_json(report: AnalysisReport) -> str:
    return json.dumps(
        {"risk_score": report.risk_score, "findings": [asdict(finding) for finding in report.findings]},
        indent=2,
    )
