from __future__ import annotations

from pathlib import Path

import typer

from mcp_guard.benchmark import (
    render_benchmark_json,
    render_benchmark_markdown,
    run_benchmark,
)
from mcp_guard.diff import diff_tools
from mcp_guard.hashing import canonical_hash, render_baseline
from mcp_guard.models import ScanResult
from mcp_guard.policy import apply_policy, load_policy, policy_fail_on, render_default_policy, should_fail
from mcp_guard.reports import render_json, render_markdown, render_sarif
from mcp_guard.rules.catalog import all_rules, get_rule, render_rules_json, render_rules_markdown
from mcp_guard.scanner import scan_path
from mcp_guard.summary import build_summary

app = typer.Typer(help="mcp-guard static security scanner")

REPORT_FORMATS = {"markdown", "json", "sarif"}
TEXT_FORMATS = {"markdown", "json"}


def _fail_unsupported_format(format: str, allowed: set[str]) -> None:
    supported = ", ".join(sorted(allowed))
    typer.echo(f"Unsupported format: {format}. Supported formats: {supported}", err=True)
    raise typer.Exit(2)


def _render_scan_result(result: ScanResult, format: str) -> str:
    if format not in REPORT_FORMATS:
        _fail_unsupported_format(format, REPORT_FORMATS)
    if format == "json":
        return render_json(result)
    if format == "sarif":
        return render_sarif(result)
    return render_markdown(result)


def _write_or_echo(rendered: str, out: str | None) -> None:
    if out:
        Path(out).write_text(rendered, encoding="utf-8")
    else:
        typer.echo(rendered)


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
    rendered = _render_scan_result(result, format)
    _write_or_echo(rendered, output_path)
    effective_fail_on = policy_fail_on(fail_on, loaded_policy)
    if should_fail(result.summary.max_severity, effective_fail_on):
        raise typer.Exit(1)


@app.command("hash")
def hash_cmd(
    path: str,
    out: str | None = typer.Option(None, "--out"),
):
    if out:
        Path(out).write_text(render_baseline(path), encoding="utf-8")
    else:
        typer.echo(canonical_hash(path))


@app.command()
def diff(
    baseline: str,
    current: str,
    format: str = typer.Option("markdown", "--format"),
    out: str | None = typer.Option(None, "--out"),
):
    findings = diff_tools(baseline, current)
    result = ScanResult(target=f"{baseline} -> {current}", findings=findings, summary=build_summary(findings))
    rendered = _render_scan_result(result, format)
    _write_or_echo(rendered, out)


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

    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    if format == "json":
        typer.echo(render_rules_json(rules))
    else:
        typer.echo(render_rules_markdown(rules))


@app.command()
def benchmark(
    matrix: str = typer.Argument("examples/fixture_matrix.yaml"),
    format: str = typer.Option("markdown", "--format"),
    out: str | None = typer.Option(None, "--out"),
):
    report = run_benchmark(matrix)
    if format not in TEXT_FORMATS:
        _fail_unsupported_format(format, TEXT_FORMATS)
    rendered = render_benchmark_json(report) if format == "json" else render_benchmark_markdown(report)
    _write_or_echo(rendered, out)
    if report["failed"]:
        raise typer.Exit(1)
