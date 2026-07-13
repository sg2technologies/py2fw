from __future__ import annotations

import typer
from rich.console import Console

from py2fw.plugins.registry import load_builtin_exporters

app = typer.Typer(help="List compiler targets")
console = Console()


@app.callback(invoke_without_command=True)
def targets() -> None:
    for name in load_builtin_exporters().names():
        console.print(name)
