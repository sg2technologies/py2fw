from __future__ import annotations

from py2fw.analyzers.compliance import FAIL, PASS, compliance_report
from tests.conftest import make_ir


def _ir(policies: list[dict[str, object]]) -> object:
    return make_ir(
        objects={"internet": ["any"], "db": ["10.0.0.10"], "web": ["10.0.1.0/24"]},
        services={
            "https": {"protocol": "tcp", "port": 443},
            "mysql": {"protocol": "tcp", "port": 3306},
        },
        policies=policies,
    )


def test_clean_segmented_policy_passes_boundary_controls() -> None:
    ir = _ir(
        [
            {"name": "web_to_db", "source": ["web"], "destination": ["db"],
             "service": ["mysql"], "action": "allow", "description": "app tier"},
        ]
    )
    report = compliance_report(ir)
    status = {(r.framework, r.control): r.status for r in report.results}
    assert status[("pci", "1.4.1")] == PASS
    assert status[("nist", "SC-7")] == PASS
    assert status[("cis", "13.4")] == PASS


def test_internet_to_database_fails_pci_1_4_4() -> None:
    ir = _ir(
        [
            {"name": "bad", "source": ["internet"], "destination": ["db"],
             "service": ["mysql"], "action": "allow"},
        ]
    )
    report = compliance_report(ir, ["pci"])
    failed = {r.control for r in report.by_status(FAIL)}
    assert "1.4.4" in failed


def test_framework_filter_limits_output() -> None:
    ir = _ir([{"name": "r", "source": ["web"], "destination": ["db"],
               "service": ["mysql"], "action": "allow"}])
    report = compliance_report(ir, ["cis"])
    assert {r.framework for r in report.results} == {"cis"}


def test_any_to_any_fails_across_frameworks() -> None:
    ir = _ir(
        [
            {"name": "open", "source": ["internet"], "destination": ["internet"],
             "service": ["any"], "action": "allow"},
        ]
    )
    failed = {(r.framework, r.control) for r in compliance_report(ir).by_status(FAIL)}
    assert ("pci", "1.4.1") in failed
    assert ("nist", "SC-7") in failed
    assert ("cis", "4.4") in failed
