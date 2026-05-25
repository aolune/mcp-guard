from mcp_guard.scanner import scan_path

def test_rules_fire():
    r=scan_path("examples/dangerous_stdio_config.json")
    ids={f.id for f in r.findings}
    assert "MCG-CONFIG-002" in ids
