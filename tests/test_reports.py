from mcp_guard.reports import render_json, render_markdown, render_sarif
from mcp_guard.scanner import scan_path


def test_reports():
    r = scan_path("examples/poisoned_tool_manifest.json")
    markdown = render_markdown(r)
    assert "mcp-guard Report" in markdown
    assert "Risk score:" in markdown
    assert "Recommended policy" in markdown
    json_report = render_json(r)
    assert '"findings"' in json_report
    assert '"recommended_policy"' in json_report
    sarif = render_sarif(r)
    assert '"version": "2.1.0"' in sarif
    assert '"ruleId": "MCPG-INJ-001"' in sarif


def test_secret_values_are_masked():
    r = scan_path("examples/credential_env_mcp_config.json")
    report = render_markdown(r)
    assert "ghp_exampletoken123456" not in report
    assert "gh***56" in report
