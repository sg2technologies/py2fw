from __future__ import annotations

import typer
from rich.console import Console

from py2fw import __version__

app = typer.Typer(help="Show version")
console = Console()


@app.callback(invoke_without_command=True)
def version() -> None:
    console.print(__version__)
