from __future__ import annotations

from py2fw.analyzers.engine import analyze_ir
from py2fw.analyzers.shadow_rules import find_shadowed_rules
from py2fw.analyzers.unused_objects import find_unused_objects
from tests.conftest import make_ir


def test_flags_high_risk_database_exposure() -> None:
    ir = make_ir(
        objects={"internet": ["any"], "db": ["10.0.0.10"]},
        services={"mysql": {"protocol": "tcp", "port": 3306}},
        policies=[
            {"name": "internet_to_db", "source": ["internet"], "destination": ["db"],
             "service": ["mysql"], "action": "allow"}
        ],
    )
    report = analyze_ir(ir)
    assert report.risk_score >= 25
    assert any(f.title == "Internet to internal database" for f in report.findings)


def test_any_protocol_service_still_flags_db_exposure() -> None:
    ir = make_ir(
        objects={"internet": ["any"], "db": ["10.0.0.10"]},
        policies=[
            {"name": "wide", "source": ["internet"], "destination": ["db"], "service": ["any"],
             "action": "allow"}
        ],
    )
    titles = {f.title for f in analyze_ir(ir).findings}
    assert "Internet to internal database" in titles
    assert "Broad source to all ports" in titles


def test_broad_public_cidr_counts_as_untrusted_source() -> None:
    ir = make_ir(
        objects={"wan": ["8.0.0.0/8"], "db": ["10.0.0.10"]},
        services={"ssh": {"protocol": "tcp", "port": 22}},
        policies=[
            {"name": "r", "source": ["wan"], "destination": ["db"], "service": ["ssh"],
             "action": "allow"}
        ],
    )
    assert any(f.title == "Open SSH" for f in analyze_ir(ir).findings)


def test_unused_object_not_flagged_when_used_via_group() -> None:
    ir = make_ir(
        objects={"web": ["10.0.0.1"], "db": ["10.0.0.2"]},
        groups={"tier": ["web"]},
        services={"mysql": {"protocol": "tcp", "port": 3306}},
        policies=[
            {"name": "r", "source": ["tier"], "destination": ["db"], "service": ["mysql"],
             "action": "allow"}
        ],
    )
    unused = {f.detail for f in find_unused_objects(ir)}
    assert "web" not in unused


def test_shadowed_rule_detected_by_containment() -> None:
    ir = make_ir(
        objects={"any_net": ["0.0.0.0/0"], "host": ["10.0.0.5"], "db": ["10.0.0.10"]},
        services={"mysql": {"protocol": "tcp", "port": 3306}},
        policies=[
            {"name": "broad_deny", "source": ["any_net"], "destination": ["db"],
             "service": ["mysql"], "action": "deny"},
            {"name": "specific_allow", "source": ["host"], "destination": ["db"],
             "service": ["mysql"], "action": "allow"},
        ],
    )
    shadowed = {f.rule for f in find_shadowed_rules(ir) if f.title == "Shadowed rule"}
    assert "specific_allow" in shadowed
