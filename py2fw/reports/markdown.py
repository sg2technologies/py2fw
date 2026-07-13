from __future__ import annotations

from py2fw.analyzers.models import AnalysisReport


def render_markdown(report: AnalysisReport) -> str:
    lines = [f"Risk Score: {report.risk_score}", ""]
    for severity in ("high", "medium", "low"):
        findings = report.by_severity(severity)
        if not findings:
            continue
        lines.extend([severity.upper(), "-" * len(severity)])
        for finding in findings:
            subject = f": {finding.rule}" if finding.rule else ""
            detail = f" - {finding.detail}" if finding.detail else ""
            lines.append(f"{finding.title}{subject}{detail}")
        lines.append("")
    return "\n".join(lines).rstrip()
