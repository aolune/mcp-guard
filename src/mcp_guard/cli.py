from __future__ import annotations

import typer

from mcp_guard.diff import diff_tools
from mcp_guard.hashing import canonical_hash
from mcp_guard.models import ScanResult
from mcp_guard.reports import render_json, render_markdown, render_sarif
from mcp_guard.scanner import scan_path
from mcp_guard.policy import apply_policy, load_policy, policy_fail_on, should_fail
from mcp_guard.summary import build_summary

app = typer.Typer(help="mcp-guard static security scanner")
sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@app.command()
def scan(
    path: str,
    format: str = typer.Option("markdown", "--format"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    policy: str | None = typer.Option(None, "--policy"),
):
    result = scan_path(path)
    loaded_policy = load_policy(policy)
    result.findings = apply_policy(result.findings, loaded_policy)
    result.summary = build_summary(result.findings)
    if format == "json":
        out = render_json(result)
    elif format == "sarif":
        out = render_sarif(result)
    else:
        out = render_markdown(result)
    typer.echo(out)
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
