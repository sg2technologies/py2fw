from __future__ import annotations

from pathlib import Path

from py2fw.analyzers.engine import analyze_ir
from py2fw.cli._pipeline import compile_path, validate_path
from py2fw.parser.source_map import build_source_map

POLICY = """version: 1
objects:
  web:
    - 10.0.0.1
  bad:
    - not valid!!
services:
  s:
    protocol: tcp
    port: 80
policies:
  - name: r
    source: [web]
    destination: [ghost]
    service: [s]
    action: allow
"""


def test_source_map_resolves_nested_paths() -> None:
    sm = build_source_map(POLICY)
    assert sm.line("objects.bad") == 5
    assert sm.line("objects.bad[0]") == 6
    assert sm.line("policies[0]") == 12
    assert sm.line("policies[0].destination") == 14
    # fallback: unknown leaf resolves to nearest known ancestor
    assert sm.line("policies[0].action.extra") == 16


def test_validation_issues_carry_line_numbers(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    _, result = validate_path(policy)
    by_msg = {i.message: i.line for i in result.issues}
    assert by_msg["invalid IP, CIDR, or hostname: not valid!!"] == 6
    assert by_msg["unknown object reference: ghost"] == 12


def test_findings_carry_line_numbers() -> None:
    ir = compile_path(Path("examples/risky.yaml"))
    findings = analyze_ir(ir).findings
    any_to_any = next(f for f in findings if f.title == "Any to Any")
    assert any_to_any.line is not None
    assert any_to_any.location.startswith("policies[")
