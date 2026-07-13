from __future__ import annotations

from pathlib import Path
from typing import Literal

import typer
from rich.console import Console

from py2fw import __version__
from py2fw.analyzers.engine import analyze_ir
from py2fw.cli._pipeline import compile_path, validate_path
from py2fw.graph.renderer import render_graph
from py2fw.plugins.registry import load_builtin_exporters
from py2fw.reports.html import render_html
from py2fw.reports.json import render_json
from py2fw.reports.markdown import render_markdown

app = typer.Typer(help="Py2FW firewall Policy-as-Code compiler")
console = Console()


@app.command("validate")
def validate_command(policy: Path = typer.Argument(..., exists=True, dir_okay=False)) -> None:
    _, result = validate_path(policy)
    if result.ok:
        console.print("[green]Policy is valid[/green]")
    for issue in result.issues:
        color = "red" if issue.severity == "error" else "yellow"
        console.print(f"[{color}]{issue.severity.upper()}[/{color}] {issue.location}: {issue.message}")
    if not result.ok:
        raise typer.Exit(code=1)


@app.command("compile")
def compile_command(
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


@app.command("analyze")
def analyze_command(
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


@app.command("graph")
def graph_command(
    policy: Path = typer.Argument(..., exists=True, dir_okay=False),
    output: Path = typer.Option(Path("policy.svg"), "--output", "-o"),
) -> None:
    rendered = render_graph(compile_path(policy), output)
    console.print(f"[green]Wrote {rendered}[/green]")


@app.command("explain")
def explain_command(
    policy: Path = typer.Argument(..., exists=True, dir_okay=False),
    rule_name: str | None = typer.Option(None, "--rule"),
) -> None:
    ir = compile_path(policy)
    rules = [rule for rule in ir.policies if rule_name is None or rule.name == rule_name]
    if not rules:
        console.print("[red]No matching rules[/red]")
        raise typer.Exit(code=1)
    for rule in rules:
        console.print(
            f"{rule.name}: {rule.action} {', '.join(rule.source)} -> "
            f"{', '.join(rule.destination)} using {', '.join(rule.services)}"
        )


@app.command("targets")
def targets_command() -> None:
    for name in load_builtin_exporters().names():
        console.print(name)


@app.command("version")
def version_command() -> None:
    console.print(__version__)


if __name__ == "__main__":
    app()
