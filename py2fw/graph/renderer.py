from __future__ import annotations

from pathlib import Path

from py2fw.compiler.ir import FirewallIR


class GraphError(RuntimeError):
    """Raised when a policy graph cannot be rendered."""


def render_graph(ir: FirewallIR, output: Path) -> Path:
    try:
        from graphviz import ExecutableNotFound

        from py2fw.graph.graphviz import build_graph
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise GraphError("graphviz Python package is not installed") from exc

    graph = build_graph(ir)
    fmt = output.suffix.lstrip(".") or "svg"
    try:
        rendered = graph.render(
            filename=output.with_suffix("").as_posix(), format=fmt, cleanup=True
        )
    except ExecutableNotFound as exc:
        raise GraphError(
            "the Graphviz 'dot' executable was not found; install Graphviz to render graphs"
        ) from exc
    return Path(rendered)
