from mcp_guard.reports import render_json, render_markdown, render_sarif
from mcp_guard.scanner import scan_path


def test_reports():
    r = scan_path("examples/poisoned_tool_manifest.json")
    assert "mcp-guard Report" in render_markdown(r)
    assert '"findings"' in render_json(r)
    sarif = render_sarif(r)
    assert '"version": "2.1.0"' in sarif
    assert '"ruleId": "MCG-TOOL-001"' in sarif
