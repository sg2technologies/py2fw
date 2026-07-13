from __future__ import annotations

from pathlib import Path

from py2fw.cli._pipeline import compile_path


def test_compile_path_accepts_example() -> None:
    ir = compile_path(Path("examples/basic.yaml"))

    assert len(ir.policies) == 2
