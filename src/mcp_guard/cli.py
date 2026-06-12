from __future__ import annotations

from pathlib import Path

import typer

from mcp_guard.diff import diff_tools
from mcp_guard.hashing import canonical_hash
from mcp_guard.models import ScanResult
from mcp_guard.policy import apply_policy, load_policy, policy_fail_on, render_default_policy, should_fail
from mcp_guard.reports import render_json, render_markdown, render_sarif
from mcp_guard.rules.catalog import all_rules, get_rule, render_rules_json, render_rules_markdown
from mcp_guard.scanner import scan_path
from mcp_guard.summary import build_summary

app = typer.Typer(help="mcp-guard static security scanner")


@app.command()
def scan(
    path: str,
    format: str = typer.Option("markdown", "--format"),
    output_path: str | None = typer.Option(None, "--out"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    policy: str | None = typer.Option(None, "--policy"),
):
    result = scan_path(path)
    loaded_policy = load_policy(policy)
    result.findings = apply_policy(result.findings, loaded_policy)
    result.summary = build_summary(result.findings)
    if format == "json":
        rendered = render_json(result)
    elif format == "sarif":
        rendered = render_sarif(result)
    else:
        rendered = render_markdown(result)
    if output_path:
        Path(output_path).write_text(rendered, encoding="utf-8")
    else:
        typer.echo(rendered)
    effective_fail_on = policy_fail_on(fail_on, loaded_policy)
    if should_fail(result.summary.max_severity, effective_fail_on):
        raise typer.Exit(1)


@app.command("hash")
def hash_cmd(path: str):
    typer.echo(canonical_hash(path))


@app.command()
def diff(baseline: str, current: str):
    findings = diff_tools(baseline, current)
    result = ScanResult(target=f"{baseline} -> {current}", findings=findings, summary=build_summary(findings))
    typer.echo(render_markdown(result))


@app.command("init-policy")
def init_policy(
    out: str | None = typer.Option(None, "--out"),
):
    policy_text = render_default_policy()
    if out:
        Path(out).write_text(policy_text, encoding="utf-8")
    else:
        typer.echo(policy_text)


@app.command()
def explain(
    rule_id: str | None = typer.Argument(None),
    format: str = typer.Option("markdown", "--format"),
):
    if rule_id:
        rule = get_rule(rule_id)
        if not rule:
            typer.echo(f"Unknown rule id: {rule_id}", err=True)
            raise typer.Exit(1)
        rules = [rule]
    else:
        rules = all_rules()

    if format == "json":
        typer.echo(render_rules_json(rules))
    else:
        typer.echo(render_rules_markdown(rules))
