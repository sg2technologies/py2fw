from __future__ import annotations

from html import escape

from py2fw.analyzers.models import AnalysisReport

_SEVERITIES = ("critical", "high", "medium", "low")


def render_html(report: AnalysisReport) -> str:
    sections: list[str] = []
    for severity in _SEVERITIES:
        findings = report.by_severity(severity)
        if not findings:
            continue
        rows = "\n".join(
            "<li>{title}{rule}{detail}</li>".format(
                title=escape(f.title),
                rule=f" &mdash; {escape(f.rule)}" if f.rule else "",
                detail=f" <em>{escape(f.detail)}</em>" if f.detail else "",
            )
            for f in findings
        )
        sections.append(f"<h2>{escape(severity.upper())}</h2>\n<ul>\n{rows}\n</ul>")
    body = "\n".join(sections) or "<p>No findings.</p>"
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">"
        "<title>Py2FW Analysis</title></head>\n<body>\n"
        "<h1>Py2FW Analysis</h1>\n"
        f"<p>Risk score: <strong>{report.risk_score}</strong></p>\n"
        f"{body}\n</body>\n</html>"
    )
