from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from py2fw.cli._pipeline import validate_path

app = typer.Typer(help="Validate a Py2FW policy")
console = Console()


@app.callback(invoke_without_command=True)
def validate(policy: Path = typer.Argument(..., exists=True, dir_okay=False)) -> None:
    _, result = validate_path(policy)
    if result.ok:
        console.print("[green]Policy is valid[/green]")
    for issue in result.issues:
        color = "red" if issue.severity == "error" else "yellow"
        console.print(f"[{color}]{issue.severity.upper()}[/{color}] {issue.location}: {issue.message}")
    if not result.ok:
        raise typer.Exit(code=1)
