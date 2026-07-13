from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from py2fw.cli._pipeline import compile_path
from py2fw.graph.renderer import render_graph

app = typer.Typer(help="Render a policy graph")
console = Console()


@app.callback(invoke_without_command=True)
def graph(
    policy: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("policy.svg"), "--output", "-o"),
) -> None:
    rendered = render_graph(compile_path(policy), output)
    console.print(f"[green]Wrote {rendered}[/green]")
