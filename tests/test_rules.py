from mcp_guard.rules.catalog import all_rules
from mcp_guard.scanner import scan_path

ALLOWED_RULE_CATEGORIES = {
    "stdio",
    "secret",
    "capability",
    "schema",
    "injection",
    "supply_chain",
}


def test_rules_fire():
    r = scan_path("examples/dangerous_stdio_config.json")
    ids = {f.id for f in r.findings}
    assert "MCPG-STDIO-003" in ids
    assert "MCPG-SECRET-001" in ids


def test_schema_text_patterns_fire_in_input_schema():
    r = scan_path("examples/poisoned_tool_manifest.json")
    ids = {f.id for f in r.findings}
    assert "MCPG-INJ-001" in ids
    assert "MCPG-CAP-004" in ids
    assert "MCPG-SCHEMA-004" in ids


def test_core_fixture_capabilities():
    cases = [
        ("examples/dangerous_shell_tool_manifest.json", "MCPG-SCHEMA-004"),
        ("examples/arbitrary_file_read_manifest.json", "MCPG-SCHEMA-002"),
        ("examples/network_exfil_tool_manifest.json", "MCPG-SCHEMA-003"),
        ("examples/overbroad_schema_manifest.json", "MCPG-SCHEMA-001"),
        ("examples/credential_env_mcp_config.json", "MCPG-SECRET-001"),
        ("examples/poisoned_readme.md", "MCPG-INJ-001"),
    ]
    for path, expected_id in cases:
        ids = {finding.id for finding in scan_path(path).findings}
        assert expected_id in ids


def test_safe_readonly_fixture_passes():
    result = scan_path("examples/safe_readonly_docs_manifest.json")
    assert result.summary.gate_result == "pass"
    assert result.summary.recommended_policy.action == "allow"


def test_rule_catalog_uses_planned_taxonomy():
    assert {rule["category"] for rule in all_rules()} <= ALLOWED_RULE_CATEGORIES


def test_network_config_findings_use_supply_chain_category():
    result = scan_path("examples/dangerous_stdio_config.json")
    network_categories = {finding.category for finding in result.findings if finding.id.startswith("MCPG-NET-")}
    assert network_categories == {"supply_chain"}
