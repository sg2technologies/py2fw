from __future__ import annotations

from pathlib import Path

import pytest
from py2fw.compiler.resolver import ResolutionError, resolve_group
from py2fw.compiler.validator import validate_document
from py2fw.parser.schema import PolicyDocument
from py2fw.parser.yaml_parser import ParseError, parse_policy
from pydantic import ValidationError


def _doc(**overrides: object) -> PolicyDocument:
    base: dict[str, object] = {
        "version": 1,
        "objects": {"web": ["10.0.0.1"], "db": ["10.0.0.2"]},
        "services": {"mysql": {"protocol": "tcp", "port": 3306}},
        "policies": [
            {
                "name": "web_to_db",
                "source": ["web"],
                "destination": ["db"],
                "service": ["mysql"],
                "action": "allow",
            }
        ],
    }
    base.update(overrides)
    return PolicyDocument.model_validate(base)


def test_valid_policy_document() -> None:
    assert validate_document(_doc()).ok


def test_invalid_endpoint_is_rejected() -> None:
    result = validate_document(_doc(objects={"bad": ["not a host name"]}))
    assert not result.ok
    assert any("invalid IP" in issue.message for issue in result.issues)


def test_any_protocol_with_port_is_rejected() -> None:
    with pytest.raises(ValidationError):
        PolicyDocument.model_validate(
            {"version": 1, "services": {"x": {"protocol": "any", "port": 80}}}
        )


def test_unknown_reference_is_error() -> None:
    result = validate_document(
        _doc(
            policies=[
                {
                    "name": "r",
                    "source": ["ghost"],
                    "destination": ["db"],
                    "service": ["mysql"],
                    "action": "allow",
                }
            ]
        )
    )
    assert not result.ok
    assert any("unknown object reference: ghost" in i.message for i in result.issues)


def test_circular_group_reference_detected() -> None:
    with pytest.raises(ResolutionError):
        resolve_group("a", {}, {"a": ["b"], "b": ["a"]})


def test_parse_policy_reports_schema_errors(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("version: 2\n", encoding="utf-8")
    with pytest.raises(ParseError) as exc:
        parse_policy(bad)
    assert "schema error" in str(exc.value)


def test_parse_policy_rejects_non_mapping(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("- 1\n- 2\n", encoding="utf-8")
    with pytest.raises(ParseError):
        parse_policy(bad)
