from __future__ import annotations

from py2fw.engine.diff import diff_policies
from py2fw.engine.evaluate import Flow, evaluate
from tests.conftest import make_ir

BASIC = dict(
    objects={"web": ["10.0.0.0/24"], "db": ["10.1.0.5"], "net": ["0.0.0.0/0"]},
    services={"mysql": {"protocol": "tcp", "port": 3306}, "web": {"protocol": "tcp", "port": 443}},
)


def _policy_ir(policies: list[dict[str, object]]) -> object:
    return make_ir(policies=policies, **BASIC)


def test_first_match_allow() -> None:
    ir = _policy_ir(
        [
            {"name": "ok", "source": ["web"], "destination": ["db"], "service": ["mysql"],
             "action": "allow"},
        ]
    )
    decision = evaluate(ir, Flow("10.0.0.5", "10.1.0.5", "tcp", 3306))
    assert decision.allowed
    assert decision.matched_rule is not None and decision.matched_rule.name == "ok"


def test_default_deny_when_no_rule_matches() -> None:
    ir = _policy_ir(
        [
            {"name": "ok", "source": ["web"], "destination": ["db"], "service": ["mysql"],
             "action": "allow"},
        ]
    )
    decision = evaluate(ir, Flow("10.0.0.5", "10.1.0.5", "tcp", 22))
    assert not decision.allowed
    assert decision.default_applied


def test_earlier_deny_wins_over_later_allow() -> None:
    ir = _policy_ir(
        [
            {"name": "block", "source": ["net"], "destination": ["db"], "service": ["mysql"],
             "action": "deny"},
            {"name": "allow", "source": ["web"], "destination": ["db"], "service": ["mysql"],
             "action": "allow"},
        ]
    )
    decision = evaluate(ir, Flow("10.0.0.5", "10.1.0.5", "tcp", 3306))
    assert not decision.allowed
    assert decision.matched_rule is not None and decision.matched_rule.name == "block"


def test_disabled_rule_is_skipped() -> None:
    ir = _policy_ir(
        [
            {"name": "ok", "source": ["web"], "destination": ["db"], "service": ["mysql"],
             "action": "allow", "enabled": False},
        ]
    )
    assert not evaluate(ir, Flow("10.0.0.5", "10.1.0.5", "tcp", 3306)).allowed


def test_diff_detects_added_and_broadened() -> None:
    old = _policy_ir(
        [
            {"name": "r", "source": ["web"], "destination": ["db"], "service": ["mysql"],
             "action": "allow"},
        ]
    )
    new = _policy_ir(
        [
            {"name": "r", "source": ["net"], "destination": ["db"], "service": ["mysql"],
             "action": "allow"},
            {"name": "extra", "source": ["web"], "destination": ["db"], "service": ["web"],
             "action": "allow"},
        ]
    )
    result = diff_policies(old, new)
    assert {c.name for c in result.added} == {"extra"}
    assert {c.name for c in result.modified} == {"r"}
    assert result.risk in {"MEDIUM", "HIGH"}


def test_diff_no_changes() -> None:
    ir = _policy_ir(
        [
            {"name": "r", "source": ["web"], "destination": ["db"], "service": ["mysql"],
             "action": "allow"},
        ]
    )
    assert diff_policies(ir, ir).changes == ()
    assert diff_policies(ir, ir).risk == "NONE"
