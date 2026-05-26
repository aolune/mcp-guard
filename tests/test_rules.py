from mcp_guard.scanner import scan_path


def test_rules_fire():
    r = scan_path("examples/dangerous_stdio_config.json")
    ids = {f.id for f in r.findings}
    assert "MCG-CONFIG-002" in ids


def test_schema_text_patterns_fire_in_input_schema():
    r = scan_path("examples/poisoned_tool_manifest.json")
    ids = {f.id for f in r.findings}
    assert "MCG-TOOL-001" in ids
    assert "MCG-TOOL-003" in ids
