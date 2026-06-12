# mcp-guard

> Static-first, no-exec-by-default admission gate for MCP servers and agent tools.

MCP servers can expose powerful capabilities: filesystem access, shell execution, browser automation, databases, cloud APIs, messaging, credentials, and network egress. Those capabilities become part of an agent's permission boundary.

**mcp-guard** helps developers and security teams review MCP servers and agent tools before they are connected or executed. It scans MCP configs, tool manifests, schemas, descriptions, README metadata, and drift baselines to identify risky capabilities and produce an admission decision.

## Why mcp-guard?

Most MCP security conversations focus on prompt injection or runtime gateways. mcp-guard takes a narrower admission-gate stance:

| Principle | Meaning |
| --- | --- |
| Static-first | Analyze config, manifest, schema, description, README, and metadata first. |
| No-exec-by-default | Do not start untrusted `npx`, `uvx`, `python`, `docker`, or stdio commands during a default scan. |
| Capability-first | Classify what the tool can do before deciding whether it looks malicious. |
| Policy-oriented | Convert findings into allow, approval, sandbox, quarantine, or deny recommendations. |
| CI-friendly | Emit Markdown, JSON, SARIF, and exit codes for admission gates. |

## Quick demo

```powershell
python -m mcp_guard scan examples/poisoned_tool_manifest.json
```

Example summary:

```text
Gate: FAIL
Max severity: CRITICAL
Risk level: L4
Risk score: 85 / 100

Recommended policy:
- Action: deny
- Require approval: yes
- Sandbox: yes
- Network: deny
```

## Detects

- risky stdio launch commands and shell wrappers
- unpinned package execution through `npx`, `uvx`, and `pipx`
- secret-like environment variables and values
- prompt injection and hidden instructions in tool metadata
- arbitrary file path, URL, command, code, and SQL parameters
- shell, file, network, browser, database, cloud, messaging, and payment capabilities
- overbroad schemas such as `additionalProperties: true`
- tool definition drift and rug-pull style changes

## Install and run locally

Future: `pipx` / `uvx` usage.

Local development:

```powershell
python -m mcp_guard scan examples/dangerous_stdio_config.json
python -m mcp_guard scan examples/poisoned_tool_manifest.json --format json
python -m mcp_guard scan examples/poisoned_tool_manifest.json --format sarif
python -m mcp_guard scan examples/poisoned_tool_manifest.json --out report.md
python -m mcp_guard scan examples/poisoned_tool_manifest.json --policy examples/policy_example.yaml --fail-on high
python -m mcp_guard hash examples/poisoned_tool_manifest.json --out baseline.json
python -m mcp_guard diff baseline.json examples/rug_pull_changed.json
python -m mcp_guard init-policy --out .mcp-guard/policy.yaml
python -m mcp_guard explain MCPG-SCHEMA-004
```

## Example fixtures

| Fixture | Purpose |
| --- | --- |
| `examples/safe_readonly_docs_manifest.json` | Safe read-only docs query. |
| `examples/dangerous_stdio_config.json` | Shell launch, curl pipe, secret env, and localhost URL. |
| `examples/credential_env_mcp_config.json` | Secret-like env exposure. |
| `examples/poisoned_tool_manifest.json` | Prompt injection plus file, network, and shell capability. |
| `examples/dangerous_shell_tool_manifest.json` | Free-form command execution parameter. |
| `examples/arbitrary_file_read_manifest.json` | Free-form file path read. |
| `examples/arbitrary_file_write_manifest.json` | Free-form file write. |
| `examples/network_exfil_tool_manifest.json` | Free-form webhook upload. |
| `examples/overbroad_schema_manifest.json` | Overbroad schema shape. |
| `examples/rug_pull_baseline.json` and `examples/rug_pull_changed.json` | Tool definition drift. |

## Risk levels

| Level | Meaning | Default policy |
| --- | --- | --- |
| L0 | Informational or no meaningful tool capability. | Allow |
| L1 | Bounded read-only capability. | Allow |
| L2 | Sensitive read or constrained network/schema risk. | Allow with constraints |
| L3 | Write, messaging, database, cloud, arbitrary file, or outbound capability. | Require approval |
| L4 | Shell, code execution, credential access, exfiltration, payment, or destructive capability. | Deny by default or sandbox with explicit approval |

## Policy

Use `--policy` with a small YAML policy:

```yaml
version: 1
profile: enterprise-strict
fail_on: high
ignore_finding_ids: []
deny_capabilities:
  - shell_exec
  - credential_access
require_approval_levels:
  - L3
  - L4
```

## GitHub Actions and SARIF

The included CI workflow runs tests, lints the project, generates JSON/SARIF mcp-guard reports, uploads the reports as artifacts, and uploads SARIF to GitHub Code Scanning when repository permissions allow it.

Minimal workflow step:

```yaml
- run: python -m mcp_guard scan examples/poisoned_tool_manifest.json --format sarif --out mcp-guard-report.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: mcp-guard-report.sarif
    category: mcp-guard
```

For CI admission gates:

```powershell
python -m mcp_guard scan . --policy examples/policy_example.yaml --fail-on high
```

## Baseline drift detection

Generate a baseline without executing the MCP server:

```powershell
python -m mcp_guard hash examples/rug_pull_baseline.json --out baseline.json
```

Compare a later manifest or config against that baseline:

```powershell
python -m mcp_guard diff baseline.json examples/rug_pull_changed.json
```

The baseline stores hashes for descriptions, schemas, server launch definitions, env key names, capabilities, and risk levels. It does not store secret environment values.

## OWASP MCP mapping

mcp-guard findings include an `owasp` field and SARIF `tags` so reports can be grouped by MCP security themes.

| Rule family | Mapping |
| --- | --- |
| `MCPG-STDIO-*` | Command Injection, Supply Chain |
| `MCPG-SECRET-*` | Token Mismanagement, Context Over-Sharing |
| `MCPG-CAP-*` | Scope Creep |
| `MCPG-SCHEMA-*` | Scope Creep, Intent Flow Subversion |
| `MCPG-INJ-*` | Tool Poisoning, Context Injection |
| `MCPG-SC-*` | Supply Chain, Tool Poisoning |
| `MCPG-NET-*` | Intent Flow Subversion, Context Over-Sharing |

Use `explain` to inspect rule metadata:

```powershell
python -m mcp_guard explain MCPG-SCHEMA-004
python -m mcp_guard explain --format json
```

## Non-goals

mcp-guard is not:

- an MCP client
- an MCP gateway
- a runtime sandbox
- a malware analysis platform
- a general SAST replacement
- a guarantee that a server is safe

It identifies risky capabilities and suspicious metadata so teams can make an admission decision before connecting a tool.

## Roadmap

- v0.1: static scanner, risk scoring, policy recommendation, Markdown / JSON / SARIF reports, fixtures, tests
- v0.2: GitHub Action, SARIF hardening, OWASP MCP mapping, richer drift detection
- v0.3: optional live inspection behind explicit `--allow-exec` and command allowlists
- v0.4: runtime policy adapter and audit workflow
- v0.5: enterprise admission service inputs
