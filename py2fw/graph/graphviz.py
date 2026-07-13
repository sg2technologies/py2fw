from __future__ import annotations

from graphviz import Digraph

from py2fw.compiler.ir import FirewallIR


def build_graph(ir: FirewallIR) -> Digraph:
    graph = Digraph("py2fw", graph_attr={"rankdir": "TB"})
    graph.node("Internet", shape="oval")
    for rule in ir.policies:
        if not rule.enabled:
            continue
        for source in rule.source:
            for destination in rule.destination:
                label = f"{rule.action}: {', '.join(rule.services)}"
                graph.node(source, shape="box")
                graph.node(destination, shape="box")
                graph.edge(source, destination, label=label)
    return graph
