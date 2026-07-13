from __future__ import annotations

from html import escape

from py2fw.analyzers.models import AnalysisReport


def render_html(report: AnalysisReport) -> str:
    items = "\n".join(
        f"<li><strong>{escape(f.severity.upper())}</strong> {escape(f.title)} {escape(f.rule or '')} {escape(f.detail)}</li>"
        for f in report.findings
    )
    return f"<!doctype html><html><body><h1>Py2FW Analysis</h1><p>Risk Score: {report.risk_score}</p><ul>{items}</ul></body></html>"
