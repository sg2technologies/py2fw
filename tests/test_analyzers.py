from __future__ import annotations

from py2fw.analyzers.engine import analyze_ir
from py2fw.compiler.builder import build_ir
from py2fw.parser.schema import PolicyDocument


def test_analyzer_flags_high_risk_database_exposure() -> None:
    document = PolicyDocument.model_validate(
        {
            "version": 1,
            "objects": {"internet": ["any"], "db": ["10.0.0.10"]},
            "services": {"mysql": {"protocol": "tcp", "port": 3306}},
            "policies": [
                {
                    "name": "internet_to_db",
                    "source": ["internet"],
                    "destination": ["db"],
                    "service": ["mysql"],
                    "action": "allow",
                }
            ],
        }
    )

    report = analyze_ir(build_ir(document))

    assert report.risk_score >= 25
    assert any(finding.title == "Internet to internal database" for finding in report.findings)
