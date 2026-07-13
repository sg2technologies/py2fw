from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from py2fw.cli._pipeline import compile_path
from py2fw.plugins.registry import load_builtin_exporters

app = typer.Typer(help="Compile a Py2FW policy")
console = Console()


@app.callback(invoke_without_command=True)
def compile_policy(
    policy: Path = typer.Argument(..., exists=True, dir_okay=False),
    target: str = typer.Option(..., "--target", "-t"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    ir = compile_path(policy)
    registry = load_builtin_exporters()
    try:
        rendered = registry.create(target).export(ir)
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    if output:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote {output}[/green]")
    else:
        console.print(rendered)
