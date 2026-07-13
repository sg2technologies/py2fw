from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from py2fw.cli._pipeline import compile_path

app = typer.Typer(help="Explain compiled policy rules")
console = Console()


@app.callback(invoke_without_command=True)
def explain(
    policy: Path = typer.Argument(..., exists=True, dir_okay=False),
    rule_name: str | None = typer.Option(None, "--rule"),
) -> None:
    ir = compile_path(policy)
    rules = [rule for rule in ir.policies if rule_name is None or rule.name == rule_name]
    if not rules:
        console.print("[red]No matching rules[/red]")
        raise typer.Exit(code=1)
    for rule in rules:
        console.print(f"{rule.name}: {rule.action} {', '.join(rule.source)} -> {', '.join(rule.destination)} using {', '.join(rule.services)}")
