# mcp-guard

mcp-guard is a static-first, no-exec-by-default security scanner and risk classifier for MCP servers and agent tools.

## Detects
- tool poisoning
- prompt injection in tool metadata
- dangerous stdio commands
- secret-like env exposure
- arbitrary file/network/code execution capabilities
- rug pull / schema drift
- tool risk level L0-L4
- enterprise gate recommendation

## Quickstart
Future: `pipx` / `uvx` usage.

Local development:
- `python -m mcp_guard scan examples/dangerous_stdio_config.json`
- `python -m mcp_guard scan examples/poisoned_tool_manifest.json --format markdown`
- `python -m mcp_guard scan examples/poisoned_tool_manifest.json --format sarif`
- `python -m mcp_guard hash examples/poisoned_tool_manifest.json`
- `python -m mcp_guard diff examples/rug_pull_baseline.json examples/rug_pull_changed.json`
- `python -m mcp_guard scan examples/poisoned_tool_manifest.json --policy examples/policy_example.yaml`

## Safe-by-default
mcp-guard will not start MCP servers or execute stdio commands by default.

## Example output
```markdown
# mcp-guard Report
Target: examples/dangerous_stdio_config.json
Gate: FAIL
Max severity: HIGH
Tool risk level: L4
```

## Roadmap
- v0.1 static scanner
- v0.2 SARIF + GitHub Action hardening
- v0.3 optional live MCP inspection with explicit --allow-exec + command allowlist
- v0.4 policy YAML + enterprise gate
- v0.5 runtime tool-call policy adapter


## Policy (early preview)
Use `--policy` with a YAML file to set `fail_on` and ignore selected finding IDs.
