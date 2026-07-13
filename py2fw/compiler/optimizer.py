from __future__ import annotations

from py2fw.compiler.ir import FirewallIR


def optimize_ir(ir: FirewallIR) -> FirewallIR:
    """Return an optimized IR.

    Phase 1 keeps policy order intact because order is security-significant.
    Future optimizers can add safe deduplication and normalization passes here.
    """

    return ir
