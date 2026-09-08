from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from py2fw import __version__
from py2fw.analyzers.engine import analyze_ir
from py2fw.cli._pipeline import CompileError, compile_path, validate_path
from py2fw.compiler.ir import FirewallIR
from py2fw.compiler.validator import ValidationResult
from py2fw.engine.diff import RuleSignature, diff_policies
from py2fw.engine.evaluate import Flow, evaluate
from py2fw.exporters._helpers import describe_lossiness
from py2fw.parser.schema import PolicyDocument
from py2fw.parser.yaml_parser import ParseError
from py2fw.plugins.registry import load_builtin_exporters
from py2fw.reports.html import render_html
from py2fw.reports.json import render_json
from py2fw.reports.markdown import render_markdown

app = typer.Typer(help="Py2FW firewall Policy-as-Code compiler")
console = Console()
err_console = Console(stderr=True)

PolicyArg = Annotated[Path, typer.Argument(exists=True, dir_okay=False)]


@contextmanager
def _handled() -> Iterator[None]:
    try:
        yield
    except (ParseError, CompileError) as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc


def _compile(policy: Path) -> FirewallIR:
    with _handled():
        return compile_path(policy)


def _validate(policy: Path) -> tuple[PolicyDocument, ValidationResult]:
    with _handled():
        return validate_path(policy)


@app.command("validate")
def validate_command(policy: PolicyArg) -> None:
    _, result = _validate(policy)
    if result.ok:
        console.print("[green]Policy is valid[/green]")
    for issue in result.issues:
        color = "red" if issue.severity == "error" else "yellow"
        console.print(
            f"[{color}]{issue.severity.upper()}[/{color}] {issue.location}: {issue.message}"
        )
    if not result.ok:
        raise typer.Exit(code=1)


@app.command("compile")
def compile_command(
    policy: PolicyArg,
    target: Annotated[str, typer.Option("--target", "-t")],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    allow_lossy: Annotated[bool, typer.Option("--allow-lossy")] = False,
) -> None:
    ir = _compile(policy)
    registry = load_builtin_exporters()
    try:
        exporter = registry.create(target)
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    warnings = describe_lossiness(ir, exporter.capabilities)
    for warning in warnings:
        err_console.print(f"[yellow]LOSSY[/yellow] {warning}")
    if warnings and not allow_lossy:
        err_console.print(
            "[red]refusing to emit a policy that loses semantics; "
            "pass --allow-lossy to override[/red]"
        )
        raise typer.Exit(code=3)

    rendered = exporter.export(ir)
    if output:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote {output}[/green]")
    else:
        console.print(rendered)


@app.command("analyze")
def analyze_command(
    policy: PolicyArg,
    format_name: Annotated[str, typer.Option("--format")] = "markdown",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    report = analyze_ir(_compile(policy))
    renderers = {"markdown": render_markdown, "json": render_json, "html": render_html}
    if format_name not in renderers:
        console.print(f"[red]unknown format: {format_name}[/red]")
        raise typer.Exit(code=2)
    rendered = renderers[format_name](report)
    if output:
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote {output}[/green]")
    else:
        console.print(rendered)


@app.command("simulate")
def simulate_command(
    policy: PolicyArg,
    source: Annotated[str, typer.Option("--src", "-s", help="Source IP address")],
    destination: Annotated[str, typer.Option("--dst", "-d", help="Destination IP address")],
    port: Annotated[int | None, typer.Option("--port", "-p")] = None,
    protocol: Annotated[str, typer.Option("--protocol")] = "tcp",
) -> None:
    decision = evaluate(_compile(policy), Flow(source, destination, protocol, port))
    color = "green" if decision.allowed else "red"
    console.print(f"[{color}]RESULT: {decision.verdict}[/{color}]")
    if decision.matched_rule is not None:
        console.print(f"Matched rule: {decision.matched_rule.name} ({decision.action})")
    else:
        console.print("No rule matched; implicit default deny applied.")
    if not decision.allowed:
        raise typer.Exit(code=1)


@app.command("explain")
def explain_command(
    policy: PolicyArg,
    rule_name: Annotated[str | None, typer.Option("--rule")] = None,
    source: Annotated[str | None, typer.Option("--src", "-s")] = None,
    destination: Annotated[str | None, typer.Option("--dst", "-d")] = None,
    port: Annotated[int | None, typer.Option("--port", "-p")] = None,
    protocol: Annotated[str, typer.Option("--protocol")] = "tcp",
) -> None:
    ir = _compile(policy)
    if source and destination:
        decision = evaluate(ir, Flow(source, destination, protocol, port))
        target = protocol if port is None else f"{protocol}/{port}"
        console.print(f"Traffic {source} -> {destination} ({target})")
        console.print(f"Decision: [bold]{decision.verdict}[/bold]\n")
        for step in decision.trace:
            mark = "[green]match[/green]" if step.matched else "[dim]skip [/dim]"
            console.print(f"  {mark} {step.rule}: {step.reason}")
        if decision.default_applied:
            console.print("  [red]default[/red]: no rule matched, implicit deny")
        if not decision.allowed:
            raise typer.Exit(code=1)
        return

    rules = [r for r in ir.policies if rule_name is None or r.name == rule_name]
    if not rules:
        console.print("[red]No matching rules[/red]")
        raise typer.Exit(code=1)
    for rule in rules:
        console.print(
            f"{rule.name}: {rule.action} {', '.join(rule.source)} -> "
            f"{', '.join(rule.destination)} using {', '.join(rule.services)}"
        )


@app.command("diff")
def diff_command(
    old: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    new: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    result = diff_policies(_compile(old), _compile(new))
    if not result.changes:
        console.print("No semantic changes.")
        return
    for change in result.added:
        console.print(f"[green]+ {change.name}[/green] added ({_action(change.after)})")
    for change in result.removed:
        console.print(f"[red]- {change.name}[/red] removed ({_action(change.before)})")
    for change in result.modified:
        console.print(f"[yellow]~ {change.name}[/yellow] {'; '.join(change.notes)}")
    console.print(
        f"\n{len(result.added)} added, {len(result.removed)} removed, "
        f"{len(result.modified)} modified"
    )
    console.print(f"Security impact: [bold]{result.risk}[/bold]")


@app.command("graph")
def graph_command(
    policy: PolicyArg,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("policy.svg"),
) -> None:
    from py2fw.graph.renderer import GraphError, render_graph

    try:
        rendered = render_graph(_compile(policy), output)
    except GraphError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    console.print(f"[green]Wrote {rendered}[/green]")


@app.command("targets")
def targets_command() -> None:
    registry = load_builtin_exporters()
    for name in registry.names():
        console.print(f"{name:<12} {registry.create(name).description}")


@app.command("version")
def version_command() -> None:
    console.print(__version__)


def _action(signature: RuleSignature | None) -> str:
    return signature.action if signature is not None else "?"


if __name__ == "__main__":
    app()
