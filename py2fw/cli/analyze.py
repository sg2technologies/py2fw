from __future__ import annotations

from pathlib import Path
from typing import Literal

import typer
from rich.console import Console

from py2fw.analyzers.engine import analyze_ir
from py2fw.cli._pipeline import compile_path
from py2fw.reports.html import render_html
from py2fw.reports.json import render_json
from py2fw.reports.markdown import render_markdown

app = typer.Typer(help="Analyze policy risk")
console = Console()


@app.callback(invoke_without_command=True)
def analyze(
    policy: Path = typer.Argument(..., exists=True, dir_okay=False),
    format_name: Literal["markdown", "json", "html"] = typer.Option("markdown", "--format"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    report = analyze_ir(compile_path(policy))
    rendered = {
        "markdown": render_markdown,
        "json": render_json,
        "html": render_html,
    }[format_name](report)
    if output:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote {output}[/green]")
    else:
        console.print(rendered)
