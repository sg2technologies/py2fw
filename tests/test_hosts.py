from __future__ import annotations

import json
from pathlib import Path

from py2fw.compiler.builder import build_ir
from py2fw.compiler.hosts import resolve_document_hosts
from py2fw.parser.yaml_parser import parse_policy_with_source

POLICY = """version: 1
objects:
  site: [example.com]
  db: [10.0.0.1]
services:
  https: {protocol: tcp, port: 443}
policies:
  - {name: r, source: [site], destination: [db], service: [https], action: allow}
"""


def _write(tmp_path: Path) -> Path:
    policy = tmp_path / "p.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    return policy


def test_hostnames_pass_through_when_resolution_disabled(tmp_path: Path) -> None:
    policy = _write(tmp_path)
    document, source = parse_policy_with_source(policy)
    result = resolve_document_hosts(document, policy, do_dns=False)
    assert result.mapping == {}
    assert result.unresolved == ("example.com",)
    ir = build_ir(document, source, host_map=result.mapping)
    assert ir.addresses["site"].values == ("example.com",)


def test_resolution_writes_and_reuses_lockfile(tmp_path: Path) -> None:
    policy = _write(tmp_path)
    document, source = parse_policy_with_source(policy)
    calls: list[str] = []

    def resolver(host: str) -> list[str]:
        calls.append(host)
        return ["93.184.216.34/32"]

    first = resolve_document_hosts(document, policy, do_dns=True, resolver=resolver)
    assert first.mapping == {"example.com": ("93.184.216.34/32",)}
    lock = policy.with_name("p.py2fw-lock.json")
    assert lock.exists()
    assert json.loads(lock.read_text())["hosts"]["example.com"]["addresses"] == ["93.184.216.34/32"]

    # Second run reuses the lock and does not call the resolver again.
    resolve_document_hosts(document, policy, do_dns=True, resolver=resolver)
    assert calls == ["example.com"]

    ir = build_ir(document, source, host_map=first.mapping)
    assert ir.addresses["site"].values == ("93.184.216.34/32",)


def test_refresh_forces_re_resolution(tmp_path: Path) -> None:
    policy = _write(tmp_path)
    document, _ = parse_policy_with_source(policy)
    resolve_document_hosts(document, policy, do_dns=True, resolver=lambda h: ["1.1.1.1/32"])
    refreshed = resolve_document_hosts(
        document, policy, do_dns=True, refresh=True, resolver=lambda h: ["2.2.2.2/32"]
    )
    assert refreshed.mapping == {"example.com": ("2.2.2.2/32",)}
