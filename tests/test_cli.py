from typer.testing import CliRunner

from mcp_guard.cli import app


runner = CliRunner()


def test_scan_json_and_markdown_formats():
    json_result = runner.invoke(
        app,
        ["scan", "examples/poisoned_tool_manifest.json", "--format", "json"],
    )
    assert json_result.exit_code == 0
    assert '"recommended_policy"' in json_result.stdout

    markdown_result = runner.invoke(
        app,
        ["scan", "examples/poisoned_tool_manifest.json", "--format", "markdown"],
    )
    assert markdown_result.exit_code == 0
    assert "Recommended policy" in markdown_result.stdout


def test_scan_out_writes_report(tmp_path):
    output = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "scan",
            "examples/poisoned_tool_manifest.json",
            "--format",
            "markdown",
            "--out",
            str(output),
        ],
    )
    assert result.exit_code == 0
    assert "mcp-guard Report" in output.read_text(encoding="utf-8")


def test_scan_fail_on_high_exits_nonzero():
    result = runner.invoke(
        app,
        ["scan", "examples/poisoned_tool_manifest.json", "--fail-on", "high"],
    )
    assert result.exit_code == 1


def test_init_policy_outputs_template(tmp_path):
    output = tmp_path / "policy.yaml"
    result = runner.invoke(app, ["init-policy", "--out", str(output)])
    assert result.exit_code == 0
    policy = output.read_text(encoding="utf-8")
    assert "deny_capabilities" in policy
    assert "require_approval_levels" in policy


def test_explain_rule_markdown():
    result = runner.invoke(app, ["explain", "MCPG-SCHEMA-004"])
    assert result.exit_code == 0
    assert "dangerous command or code parameter" in result.stdout
    assert "OWASP MCP:" in result.stdout


def test_explain_all_rules_json():
    result = runner.invoke(app, ["explain", "--format", "json"])
    assert result.exit_code == 0
    assert '"id": "MCPG-SCHEMA-004"' in result.stdout
    assert '"owasp"' in result.stdout


def test_explain_unknown_rule_fails():
    result = runner.invoke(app, ["explain", "MCPG-NOPE-999"])
    assert result.exit_code == 1
    assert "Unknown rule id" in result.stderr
