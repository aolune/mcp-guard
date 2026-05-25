from __future__ import annotations

import typer

from mcp_guard.diff import diff_tools
from mcp_guard.hashing import canonical_hash
from mcp_guard.models import ScanResult
from mcp_guard.reports import render_json, render_markdown, render_sarif
from mcp_guard.risk import gate_from_findings, max_risk, max_severity
from mcp_guard.scanner import scan_path
from mcp_guard.policy import apply_policy, load_policy, policy_fail_on, should_fail

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
    result.summary.total_findings = len(result.findings)
    result.summary.max_severity = max_severity(result.findings)
    result.summary.tool_risk_level = max_risk(result.findings)
    result.summary.gate_result = gate_from_findings(result.findings)
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
    result = ScanResult(
        target=f"{baseline} -> {current}",
        findings=findings,
        summary={
            "total_findings": len(findings),
            "max_severity": max_severity(findings),
            "tool_risk_level": max_risk(findings),
            "gate_result": gate_from_findings(findings),
            "approval_required": any(f.severity in {"high", "critical"} for f in findings),
            "sandbox_required": any(f.risk_level == "L4" for f in findings),
            "egress_review_required": False,
            "credential_review_required": False,
        },
    )
    typer.echo(render_markdown(result))
