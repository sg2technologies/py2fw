from __future__ import annotations

from py2fw.compiler.validator import validate_document
from py2fw.parser.schema import PolicyDocument


def test_valid_policy_document() -> None:
    document = PolicyDocument.model_validate(
        {
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
    )

    result = validate_document(document)

    assert result.ok


def test_invalid_endpoint_is_rejected() -> None:
    document = PolicyDocument.model_validate(
        {
            "version": 1,
            "objects": {"bad": ["not a host name"]},
            "services": {"https": {"protocol": "tcp", "port": 443}},
            "policies": [
                {
                    "name": "bad_rule",
                    "source": ["bad"],
                    "destination": ["any"],
                    "service": ["https"],
                    "action": "allow",
                }
            ],
        }
    )

    result = validate_document(document)

    assert not result.ok
    assert "invalid IP" in result.issues[0].message
