from __future__ import annotations

import json
from typing import Any

from mcp_guard.rules.text_patterns import CAPABILITY_KEYWORDS
from mcp_guard.standards import owasp_for_rule

_STATIC_RULES: dict[str, dict[str, Any]] = {
    "MCPG-STDIO-001": {
        "title": "stdio command configured",
        "category": "stdio",
        "capability": "code_exec",
        "severity": "high",
        "risk_level": "L3",
        "policy_action": "require_approval",
        "description": "A local stdio server command is configured.",
        "recommendation": "Review before connecting; prefer pinned packages and sandboxed execution.",
    },
    "MCPG-STDIO-002": {
        "title": "unpinned package execution",
        "category": "supply_chain",
        "capability": "supply_chain",
        "severity": "high",
        "risk_level": "L3",
        "policy_action": "require_approval",
        "description": "A package launcher such as npx, uvx, or pipx is used without a version pin.",
        "recommendation": "Pin package versions or digests before approval.",
    },
    "MCPG-STDIO-003": {
        "title": "dangerous shell command",
        "category": "stdio",
        "capability": "shell_exec",
        "severity": "critical",
        "risk_level": "L4",
        "policy_action": "deny",
        "description": "Shell or command-execution pattern appears in the MCP server launch config.",
        "recommendation": "Deny by default or require sandboxed explicit approval.",
    },
    "MCPG-SECRET-001": {
        "title": "secret-like environment variable configured",
        "category": "secret",
        "capability": "credential_access",
        "severity": "high",
        "risk_level": "L4",
        "policy_action": "deny",
        "description": "A secret-like environment variable is passed into the MCP server runtime.",
        "recommendation": "Use scoped short-lived credentials and avoid broad secrets.",
    },
    "MCPG-SECRET-002": {
        "title": "secret-like environment value configured",
        "category": "secret",
        "capability": "credential_access",
        "severity": "high",
        "risk_level": "L4",
        "policy_action": "deny",
        "description": "An environment value resembles a token, key, or signed credential.",
        "recommendation": "Rotate exposed test secrets and inject scoped runtime credentials.",
    },
    "MCPG-NET-001": {
        "title": "non-https remote MCP url",
        "category": "config",
        "capability": "network_fetch",
        "severity": "medium",
        "risk_level": "L2",
        "policy_action": "allow_with_constraints",
        "description": "A remote MCP URL does not use HTTPS.",
        "recommendation": "Require HTTPS and certificate validation for remote MCP servers.",
    },
    "MCPG-NET-002": {
        "title": "localhost/private/metadata MCP url",
        "category": "config",
        "capability": "network_fetch",
        "severity": "high",
        "risk_level": "L4",
        "policy_action": "deny",
        "description": "A remote MCP URL points to a local, private, or metadata endpoint.",
        "recommendation": "Block private and metadata endpoints unless explicitly reviewed.",
    },
    "MCPG-INJ-001": {
        "title": "prompt injection phrase in tool metadata",
        "category": "injection",
        "capability": "prompt_injection",
        "severity": "high",
        "risk_level": "L3",
        "policy_action": "quarantine",
        "description": "Tool metadata contains instruction-like language visible to the model.",
        "recommendation": "Quarantine the metadata and require manual review before approval.",
    },
    "MCPG-INJ-002": {
        "title": "hidden or obfuscated instruction in tool metadata",
        "category": "injection",
        "capability": "prompt_injection",
        "severity": "medium",
        "risk_level": "L2",
        "policy_action": "quarantine",
        "description": "Tool metadata contains hidden, obfuscated, or secrecy-oriented markers.",
        "recommendation": "Require manual review and remove hidden instructions.",
    },
    "MCPG-SCHEMA-001": {
        "title": "free-form object schema",
        "category": "schema",
        "capability": "overbroad_schema",
        "severity": "medium",
        "risk_level": "L2",
        "policy_action": "allow_with_constraints",
        "description": "Schema allows additional free-form parameters.",
        "recommendation": "Set additionalProperties=false and enumerate supported parameters.",
    },
    "MCPG-SCHEMA-002": {
        "title": "unbounded file path parameter",
        "category": "schema",
        "capability": "file_read",
        "severity": "high",
        "risk_level": "L3",
        "policy_action": "require_approval",
        "description": "Schema accepts a free-form file path without constraints.",
        "recommendation": "Add allowed roots, path patterns, and per-call approval.",
    },
    "MCPG-SCHEMA-003": {
        "title": "unbounded url parameter",
        "category": "schema",
        "capability": "network_send",
        "severity": "high",
        "risk_level": "L3",
        "policy_action": "require_approval",
        "description": "Schema accepts a free-form URL without allowed domain constraints.",
        "recommendation": "Enforce allowed domains and deny outbound writes by default.",
    },
    "MCPG-SCHEMA-004": {
        "title": "dangerous command or code parameter",
        "category": "schema",
        "capability": "shell_exec",
        "severity": "critical",
        "risk_level": "L4",
        "policy_action": "deny",
        "description": "Schema accepts a free-form command, script, exec, or code parameter.",
        "recommendation": "Remove generic execution parameters or enumerate safe actions.",
    },
    "MCPG-SCHEMA-005": {
        "title": "free-form sql parameter",
        "category": "schema",
        "capability": "database_query",
        "severity": "high",
        "risk_level": "L3",
        "policy_action": "require_approval",
        "description": "Schema appears to accept arbitrary SQL text.",
        "recommendation": "Use parameterized operations or a constrained query builder.",
    },
    "MCPG-SC-001": {
        "title": "capability escalation after baseline",
        "category": "supply_chain",
        "capability": "supply_chain",
        "severity": "high",
        "risk_level": "L3",
        "policy_action": "require_approval",
        "description": "Tool definition changed in a way that introduces higher-risk capabilities.",
        "recommendation": "Fail admission and require security re-approval.",
    },
    "MCPG-SC-002": {
        "title": "tool definition hash changed",
        "category": "supply_chain",
        "capability": "supply_chain",
        "severity": "high",
        "risk_level": "L3",
        "policy_action": "require_approval",
        "description": "Tool schema or description changed compared to baseline.",
        "recommendation": "Treat as potential rug pull and require security re-review.",
    },
    "MCPG-SC-003": {
        "title": "tool added",
        "category": "supply_chain",
        "capability": "supply_chain",
        "severity": "medium",
        "risk_level": "L3",
        "policy_action": "require_approval",
        "description": "A new tool was introduced after baseline.",
        "recommendation": "Run the approval workflow for newly added tools.",
    },
    "MCPG-SC-004": {
        "title": "tool removed",
        "category": "supply_chain",
        "capability": "supply_chain",
        "severity": "low",
        "risk_level": "L1",
        "policy_action": "allow",
        "description": "A previously approved tool is missing from the current manifest.",
        "recommendation": "Review removal impact and trust-chain implications.",
    },
    "MCPG-SC-005": {
        "title": "server launch definition changed",
        "category": "supply_chain",
        "capability": "supply_chain",
        "severity": "high",
        "risk_level": "L3",
        "policy_action": "require_approval",
        "description": "Server command, args, env keys, transport, or URL changed after baseline.",
        "recommendation": "Require security re-review before trusting the updated launch config.",
    },
    "MCPG-SC-006": {
        "title": "server launch definition added",
        "category": "supply_chain",
        "capability": "supply_chain",
        "severity": "medium",
        "risk_level": "L3",
        "policy_action": "require_approval",
        "description": "A new MCP server launch configuration was introduced after baseline.",
        "recommendation": "Run admission review for the newly added server.",
    },
    "MCPG-SC-007": {
        "title": "server launch definition removed",
        "category": "supply_chain",
        "capability": "supply_chain",
        "severity": "low",
        "risk_level": "L1",
        "policy_action": "allow",
        "description": "An MCP server launch configuration was removed after baseline.",
        "recommendation": "Review removal impact and update approval records.",
    },
}


def _capability_rules() -> dict[str, dict[str, Any]]:
    rules = {}
    for rule_id, raw in CAPABILITY_KEYWORDS.items():
        rules[rule_id] = {
            "title": raw["title"],
            "category": "capability",
            "capability": raw["capability"],
            "severity": raw["severity"],
            "risk_level": raw["risk_level"],
            "policy_action": raw["policy_action"],
            "description": "Tool metadata or schema suggests a sensitive capability.",
            "recommendation": "Map the capability to approval, sandboxing, and least privilege.",
        }
    return rules


def all_rules() -> list[dict[str, Any]]:
    rules = {**_STATIC_RULES, **_capability_rules()}
    out = []
    for rule_id in sorted(rules):
        item = {"id": rule_id, **rules[rule_id], "owasp": owasp_for_rule(rule_id)}
        out.append(item)
    return out


def get_rule(rule_id: str) -> dict[str, Any] | None:
    normalized = rule_id.upper()
    for rule in all_rules():
        if rule["id"] == normalized:
            return rule
    return None


def render_rules_json(rules: list[dict[str, Any]]) -> str:
    return json.dumps(rules, indent=2)


def render_rules_markdown(rules: list[dict[str, Any]]) -> str:
    if len(rules) == 1:
        rule = rules[0]
        lines = [
            f"# {rule['id']} {rule['title']}",
            "",
            f"Category: {rule['category']}",
            f"Capability: {rule['capability']}",
            f"Severity: {str(rule['severity']).upper()}",
            f"Risk level: {rule['risk_level']}",
            f"Policy action: {rule['policy_action']}",
            f"OWASP MCP: {', '.join(rule['owasp']) if rule['owasp'] else 'n/a'}",
            "",
            f"Description: {rule['description']}",
            "",
            f"Recommendation: {rule['recommendation']}",
        ]
        return "\n".join(lines)

    lines = [
        "# mcp-guard Rules",
        "",
        "| Rule | Severity | Risk | Capability | Policy |",
        "| --- | --- | --- | --- | --- |",
    ]
    for rule in rules:
        lines.append(
            "| {id} | {severity} | {risk_level} | {capability} | {policy_action} |".format(
                **rule
            )
        )
    return "\n".join(lines)
