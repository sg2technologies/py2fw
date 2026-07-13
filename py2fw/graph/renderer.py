from __future__ import annotations

from pathlib import Path

from py2fw.compiler.ir import FirewallIR


def render_graph(ir: FirewallIR, output: Path) -> Path:
    from py2fw.graph.graphviz import build_graph

    graph = build_graph(ir)
    rendered = graph.render(filename=output.with_suffix("").as_posix(), format=output.suffix.lstrip(".") or "svg", cleanup=True)
    return Path(rendered)
