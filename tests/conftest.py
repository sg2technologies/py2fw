from __future__ import annotations

from typing import Any

from py2fw.compiler.builder import build_ir
from py2fw.compiler.ir import FirewallIR
from py2fw.parser.schema import PolicyDocument


def make_ir(**document: Any) -> FirewallIR:
    document.setdefault("version", 1)
    return build_ir(PolicyDocument.model_validate(document))
