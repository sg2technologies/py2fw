from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from py2fw import __version__
from py2fw.analyzers.compliance import (
    FRAMEWORKS,
    ComplianceReport,
    compliance_report,
    framework_title,
)
from py2fw.analyzers.engine import analyze_ir
from py2fw.analyzers.gate import SEVERITY_RANK, VIOLATION, WAIVED, WARNING, GateReport
from py2fw.cli._pipeline import (
    CompileError,
    PolicyCheck,
    RenderedConfig,
    check_path,
    compile_path,
    render_config,
    validate_path,
)
from py2fw.compiler.ir import FirewallIR
from py2fw.compiler.validator import ValidationResult
from py2fw.enforcement.baseline import BaselineError
from py2fw.engine.diff import RuleSignature, diff_policies
from py2fw.engine.evaluate import Flow, evaluate
from py2fw.parser.schema import PolicyDocument
from py2fw.parser.yaml_parser import ParseError
from py2fw.plugins.registry import load_builtin_exporters
from py2fw.release import audit as audit_log
from py2fw.release.plan import (
    DEFAULT_STATE_DIR,
    ReleaseError,
    StatePaths,
    approve_plan,
    create_plan,
    deploy_plan,
    load_plan,
    save_plan,
)
from py2fw.reports.html import render_html
from py2fw.reports.json import render_json
from py2fw.reports.markdown import render_markdown

app = typer.Typer(help="Py2FW firewall Policy-as-Code compiler")
console = Console()
err_console = Console(stderr=True)


def _emit(text: str) -> None:
    """Print machine-generated output without Rich markup/highlighting."""

    console.print(text, markup=False, highlight=False, soft_wrap=True)

PolicyArg = Annotated[Path, typer.Argument(exists=True, dir_okay=False)]
FailOnOpt = Annotated[
    str | None,
    typer.Option(
        "--fail-on",
        help=f"Lowest severity that blocks ({', '.join(SEVERITY_RANK)}); default from the "
        "baseline, else high. With a baseline it can only tighten the gate.",
    ),
]
BaselineOpt = Annotated[
    Path | None,
    typer.Option(
        "--baseline",
        "-b",
        dir_okay=False,
        help="Organisation baseline YAML (default: $PY2FW_BASELINE).",
    ),
]
EnvOpt = Annotated[
    str | None,
    typer.Option("--env", "-e", help="Environment (default: the policy's 'environment:')."),
]
StateOpt = Annotated[
    Path,
    typer.Option("--state-dir", help="Where deployed snapshots and the audit log live."),
]
NativeOpt = Annotated[
    bool,
    typer.Option("--native-syntax", help="Also validate with the vendor CLI (e.g. nft -c)."),
]


@contextmanager
def _handled() -> Iterator[None]:
    try:
        yield
    except (ParseError, CompileError, BaselineError) as exc:
        err_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(code=2) from exc


def _compile(
    policy: Path, *, resolve_hosts: bool = False, refresh_hosts: bool = False
) -> FirewallIR:
    with _handled():
        return compile_path(
            policy, resolve_hosts=resolve_hosts, refresh_hosts=refresh_hosts
        )


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
        where = f"{policy.name}:{issue.line}" if issue.line is not None else issue.location
        console.print(
            f"[{color}]{issue.severity.upper()}[/{color}] {where}: {issue.message}"
        )
    if not result.ok:
        raise typer.Exit(code=1)


def _check(
    policy: Path,
    fail_on: str | None,
    baseline: Path | None = None,
    environment: str | None = None,
    *,
    resolve_hosts: bool = False,
    refresh_hosts: bool = False,
) -> PolicyCheck:
    if fail_on is not None and fail_on not in SEVERITY_RANK:
        err_console.print(f"[red]unknown severity: {fail_on}[/red]")
        raise typer.Exit(code=2)
    with _handled():
        return check_path(
            policy,
            fail_on=fail_on,
            baseline=baseline,
            environment=environment,
            resolve_hosts=resolve_hosts,
            refresh_hosts=refresh_hosts,
        )


_VERDICT_COLORS = {VIOLATION: "red", WAIVED: "cyan", WARNING: "yellow"}


def _print_gate(policy: Path, gate: GateReport, out: Console) -> None:
    for verdict in (VIOLATION, WAIVED, WARNING):
        color = _VERDICT_COLORS[verdict]
        for item in gate.by_verdict(verdict):
            finding = item.finding
            where = f"{policy.name}:{finding.line}" if finding.line else finding.location
            subject = f" ({finding.rule})" if finding.rule else ""
            detail = f" - {finding.detail}" if finding.detail else ""
            note = f" [{item.note}]" if item.note and item.note != "validation" else ""
            message = escape(f"{where}: {finding.severity} {finding.title}{subject}{detail}{note}")
            out.print(
                f"[{color}]{verdict.upper()}[/{color}] {message}", highlight=False, soft_wrap=True
            )
    counts = ", ".join(
        f"{len(gate.by_verdict(verdict))} {verdict}" for verdict in (VIOLATION, WAIVED, WARNING)
    )
    passed_tests = sum(result.passed for result in gate.tests)
    tests = f", {passed_tests}/{len(gate.tests)} tests passed" if gate.tests else ""
    env = f"env: {gate.environment}, " if gate.environment else ""
    status = "[green]PASS[/green]" if gate.passed else "[red]FAIL[/red]"
    out.print(
        f"{status} {policy.name}: {counts}{tests} ({env}fail-on: {gate.fail_on})", soft_wrap=True
    )


def _gate_json(policy: Path, gate: GateReport) -> str:
    return json.dumps(
        {
            "policy": str(policy),
            "environment": gate.environment,
            "passed": gate.passed,
            "fail_on": gate.fail_on,
            "items": [
                {"verdict": item.verdict, "note": item.note, **asdict(item.finding)}
                for item in gate.items
            ],
            "tests": [asdict(result) for result in gate.tests],
        },
        indent=2,
    )


@app.command("check")
def check_command(
    policies: Annotated[list[Path], typer.Argument(exists=True, dir_okay=False)],
    fail_on: FailOnOpt = None,
    baseline: BaselineOpt = None,
    env: EnvOpt = None,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Deployment gate: exit 1 if any policy has a blocking violation (for CI / pre-merge)."""

    failed = False
    for policy in policies:
        gate = _check(policy, fail_on, baseline, env).gate
        failed = failed or not gate.passed
        if output_json:
            _emit(_gate_json(policy, gate))
        else:
            _print_gate(policy, gate, console)
    if failed:
        raise typer.Exit(code=1)


@app.command("test")
def test_command(
    policy: PolicyArg,
    baseline: BaselineOpt = None,
    env: EnvOpt = None,
) -> None:
    """Run the policy's and the baseline's security regression tests."""

    results = _check(policy, None, baseline, env).gate.tests
    if not results:
        console.print("No regression tests defined.")
        return
    for result in results:
        mark = "[green]PASS[/green]" if result.passed else "[red]FAIL[/red]"
        console.print(f"{mark} {escape(result.name)} ({result.origin}): {escape(result.detail)}")
    failed = [result for result in results if not result.passed]
    console.print(f"{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        raise typer.Exit(code=1)


def _render(ir: FirewallIR, target: str, native: bool) -> RenderedConfig:
    try:
        return render_config(ir, target, native_syntax=native)
    except KeyError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc


def _print_checks(rendered: RenderedConfig, out: Console) -> None:
    for check in rendered.checks:
        mark = "[green]PASS[/green]" if check.passed else "[red]FAIL[/red]"
        out.print(f"{mark} {check.kind}: {escape(check.detail)}", soft_wrap=True)


@app.command("verify")
def verify_command(
    policy: PolicyArg,
    target: Annotated[str, typer.Option("--target", "-t")],
    native_syntax: NativeOpt = False,
) -> None:
    """Validate the generated configuration: syntax and comparison with the policy."""

    rendered = _render(_compile(policy), target, native_syntax)
    _print_checks(rendered, console)
    for warning in rendered.lossy:
        console.print(f"[yellow]LOSSY[/yellow] {escape(warning)}")
    if not rendered.verified:
        raise typer.Exit(code=5)


@app.command("compile")
def compile_command(
    policy: PolicyArg,
    target: Annotated[str, typer.Option("--target", "-t")],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    allow_lossy: Annotated[bool, typer.Option("--allow-lossy")] = False,
    resolve_hosts: Annotated[bool, typer.Option("--resolve-hosts")] = False,
    refresh_hosts: Annotated[bool, typer.Option("--refresh-hosts")] = False,
    fail_on: FailOnOpt = None,
    baseline: BaselineOpt = None,
    env: EnvOpt = None,
    native_syntax: NativeOpt = False,
) -> None:
    if target not in load_builtin_exporters().names():
        err_console.print(f"[red]unknown target: {target}[/red]")
        raise typer.Exit(code=2)
    check = _check(
        policy, fail_on, baseline, env, resolve_hosts=resolve_hosts, refresh_hosts=refresh_hosts
    )
    if not check.gate.passed:
        _print_gate(policy, check.gate, err_console)
        err_console.print(
            "[red]refusing to emit a policy with blocking violations; fix the rules or add "
            "a time-boxed entry under 'exceptions:'[/red]"
        )
        raise typer.Exit(code=4)
    if not check.controls.target_allowed(target):
        allowed = ", ".join(check.controls.allowed_targets)
        err_console.print(
            f"[red]target {target} is not approved for {check.controls.environment}; "
            f"allowed: {allowed}[/red]"
        )
        raise typer.Exit(code=4)

    rendered = _render(check.ir, target, native_syntax)
    for warning in rendered.lossy:
        err_console.print(f"[yellow]LOSSY[/yellow] {escape(warning)}")
    if rendered.lossy and not allow_lossy:
        err_console.print(
            "[red]refusing to emit a policy that loses semantics; "
            "pass --allow-lossy to override[/red]"
        )
        raise typer.Exit(code=3)
    if not rendered.verified:
        _print_checks(rendered, err_console)
        err_console.print("[red]generated configuration failed verification[/red]")
        raise typer.Exit(code=5)

    if output:
        output.write_text(rendered.text, encoding="utf-8")
        console.print(f"[green]Wrote {output}[/green]")
    else:
        _emit(rendered.text)


def _print_release_error(exc: ReleaseError) -> None:
    err_console.print(f"[red]{escape(str(exc))}[/red]")
    for reason in exc.reasons:
        err_console.print(f"  - {escape(reason)}", soft_wrap=True)


@app.command("plan")
def plan_command(
    policy: PolicyArg,
    target: Annotated[str, typer.Option("--target", "-t")],
    author: Annotated[str, typer.Option("--author", help="Who is proposing this change.")],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("py2fw-plan.json"),
    fail_on: FailOnOpt = None,
    baseline: BaselineOpt = None,
    env: EnvOpt = None,
    allow_lossy: Annotated[bool, typer.Option("--allow-lossy")] = False,
    native_syntax: NativeOpt = False,
    state_dir: StateOpt = DEFAULT_STATE_DIR,
) -> None:
    """Gate, verify and diff a change for review; writes a plan file to approve and deploy."""

    with _handled():
        try:
            plan = create_plan(
                policy,
                target,
                author=author,
                baseline=baseline,
                environment=env,
                fail_on=fail_on,
                allow_lossy=allow_lossy,
                native_syntax=native_syntax,
                state=StatePaths(state_dir),
            )
        except ReleaseError as exc:
            _print_release_error(exc)
            raise typer.Exit(code=2) from exc
    save_plan(plan, output)
    content = plan["content"]
    console.print(f"[bold]Plan {plan['plan_id'][:12]}[/bold] {content['target']} "
                  f"({content['environment'] or 'no environment'}) by {content['author']}")
    console.print("\n[bold]Policy changes[/bold]")
    for line in content["policy_changes"]:
        console.print(f"  {escape(line)}")
    console.print("\n[bold]Configuration diff[/bold]")
    _emit(content["config_diff"] or "  (no change from deployed configuration)")
    gate = content["gate"]
    console.print(
        f"\nGate: {'PASS' if gate['passed'] else 'FAIL'} - {len(gate['violations'])} violation, "
        f"{len(gate['waived'])} waived, {gate['warnings']} warning"
    )
    for check in content["verification"]:
        console.print(f"Verify {check['kind']}: {'PASS' if check['passed'] else 'FAIL'}")
    console.print(f"Approvals required: {content['required_approvals']}")
    console.print(f"[green]Wrote {output}[/green]")
    if not content["deployable"]:
        console.print("[red]Plan is not deployable:[/red]")
        for reason in content["blockers"]:
            console.print(f"  - {escape(reason)}", soft_wrap=True)
        raise typer.Exit(code=1)


@app.command("approve")
def approve_command(
    plan_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    by: Annotated[str, typer.Option("--by", help="Approver identity (not the plan author).")],
    comment: Annotated[str, typer.Option("--comment", "-m")] = "",
    state_dir: StateOpt = DEFAULT_STATE_DIR,
) -> None:
    """Record an approval on a plan file."""

    try:
        plan = approve_plan(load_plan(plan_file), by, comment=comment, state=StatePaths(state_dir))
    except ReleaseError as exc:
        _print_release_error(exc)
        raise typer.Exit(code=6) from exc
    save_plan(plan, plan_file)
    count = len(plan["approvals"])
    required = plan["content"]["required_approvals"]
    console.print(f"[green]Approved by {escape(by)}[/green] ({count}/{required} approvals)")


@app.command("deploy")
def deploy_command(
    plan_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    actor: Annotated[str, typer.Option("--actor", help="Who (or which pipeline) deploys.")],
    to: Annotated[
        Path | None, typer.Option("--to", dir_okay=False, help="Write the config here.")
    ] = None,
    run: Annotated[
        str | None,
        typer.Option("--run", help="Command to apply it; {config} is replaced by its path."),
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    state_dir: StateOpt = DEFAULT_STATE_DIR,
) -> None:
    """Re-verify an approved plan and deploy it, recording the result in the audit log."""

    with _handled():
        try:
            result = deploy_plan(
                load_plan(plan_file),
                actor=actor,
                destination=to,
                command=run,
                dry_run=dry_run,
                state=StatePaths(state_dir),
            )
        except ReleaseError as exc:
            _print_release_error(exc)
            raise typer.Exit(code=6) from exc
    approvers = ", ".join(result.approvers) or "none required"
    if result.dry_run:
        console.print(f"[green]Plan {result.plan_id[:12]} is deployable[/green] "
                      f"(approved by: {approvers})")
        return
    if result.command_output:
        _emit(result.command_output)
    where = f" to {result.destination}" if result.destination else ""
    console.print(
        f"[green]Deployed {result.plan_id[:12]}{where}[/green] (approved by: {approvers})"
    )


audit_app = typer.Typer(help="Inspect and verify the deployment audit log.")
app.add_typer(audit_app, name="audit")


@audit_app.command("verify")
def audit_verify_command(state_dir: StateOpt = DEFAULT_STATE_DIR) -> None:
    """Check the audit log's hash chain for tampering."""

    result = audit_log.verify_log(StatePaths(state_dir).audit_log)
    for problem in result.problems:
        console.print(f"[red]{escape(problem)}[/red]")
    if not result.ok:
        raise typer.Exit(code=1)
    console.print(f"[green]Audit log intact[/green] ({result.entries} entries)")


@audit_app.command("show")
def audit_show_command(
    state_dir: StateOpt = DEFAULT_STATE_DIR,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List audit log entries."""

    entries = audit_log.read_log(StatePaths(state_dir).audit_log)
    if output_json:
        _emit(json.dumps(entries, indent=2))
        return
    for entry in entries:
        target = f"{entry.get('environment') or '-'}/{entry.get('target', '-')}"
        plan = str(entry.get("plan_id", ""))[:12]
        console.print(
            f"{entry['seq']:>4} {entry['at']} {entry['event']:<15} {target:<22} "
            f"{plan} {escape(str(entry['actor']))}",
            highlight=False,
            soft_wrap=True,
        )


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
        _emit(rendered)


@app.command("compliance")
def compliance_command(
    policy: PolicyArg,
    framework: Annotated[
        list[str] | None,
        typer.Option("--framework", "-f", help=f"One or more of: {', '.join(FRAMEWORKS)}"),
    ] = None,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    frameworks = tuple(framework) if framework else FRAMEWORKS
    unknown = [f for f in frameworks if f not in FRAMEWORKS]
    if unknown:
        console.print(f"[red]unknown framework(s): {', '.join(unknown)}[/red]")
        raise typer.Exit(code=2)
    report = compliance_report(_compile(policy), frameworks)
    if output_json:
        _emit(_compliance_json(report))
    else:
        _print_compliance(report, frameworks)
    if report.by_status("fail"):
        raise typer.Exit(code=1)


def _compliance_json(report: ComplianceReport) -> str:
    import json
    from dataclasses import asdict

    return json.dumps({"controls": [asdict(r) for r in report.results]}, indent=2)


def _print_compliance(report: ComplianceReport, frameworks: tuple[str, ...]) -> None:
    marks = {"pass": "[green]PASS[/green]", "review": "[yellow]REVIEW[/yellow]",
             "fail": "[red]FAIL[/red]"}
    for name in frameworks:
        controls = report.for_framework(name)
        if not controls:
            continue
        console.print(f"\n[bold]{framework_title(name)}[/bold]")
        for control in controls:
            console.print(f"  {marks[control.status]} {control.control}  {control.title}")
            console.print(f"        {control.detail}")
    passed = len(report.by_status("pass"))
    review = len(report.by_status("review"))
    failed = len(report.by_status("fail"))
    console.print(f"\n{passed} pass, {review} review, {failed} fail")


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
