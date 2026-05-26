from __future__ import annotations

from typing import Any

from mcp_guard.models import Finding, ToolDefinition
from mcp_guard.redaction import redact_text
from mcp_guard.rules.text_patterns import PATTERN_GROUPS


def _walk(schema: Any, path: str):
    if isinstance(schema, dict):
        yield path, schema
        for k, v in schema.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(schema, list):
        for i, v in enumerate(schema):
            yield from _walk(v, f"{path}[{i}]")


def _scan_text_patterns(findings: list[Finding], text: str, location: str) -> None:
    lowered = text.lower()
    for fid, pats in PATTERN_GROUPS.items():
        for p in pats:
            if p.lower() in lowered:
                findings.append(
                    Finding(
                        id=fid,
                        title="tool metadata pattern detected",
                        severity="high" if fid != "MCG-TOOL-003" else "medium",
                        category="tool",
                        location=location,
                        evidence=redact_text(p),
                        reason="Suspicious instruction-like content in tool metadata.",
                        recommendation="Manually review and block malicious tool metadata.",
                        risk_level="L3",
                        confidence=0.85,
                    )
                )
                break


def scan_tool(tool: ToolDefinition, base_loc: str) -> list[Finding]:
    findings: list[Finding] = []
    _scan_text_patterns(findings, tool.name, f"{base_loc}.{tool.name}.name")
    _scan_text_patterns(findings, tool.description, f"{base_loc}.{tool.name}.description")

    for loc, node in _walk(tool.inputSchema, f"{base_loc}.{tool.name}.inputSchema"):
        if not isinstance(node, dict):
            continue
        for k in ("name", "description", "title"):
            v = node.get(k)
            if isinstance(v, str):
                _scan_text_patterns(findings, v, f"{loc}.{k}")

        joined = " ".join(str(node.get(k, "")) for k in ("name", "description", "title")).lower()

        if any(x in joined for x in ["file path", "filepath", "path"]):
            findings.append(
                Finding(
                    id="MCG-SCHEMA-001",
                    title="arbitrary file path parameter",
                    severity="high",
                    category="schema",
                    location=loc,
                    evidence=redact_text(joined[:120]),
                    reason="Schema appears to accept arbitrary file path input.",
                    recommendation="Apply path allowlist and sandbox filesystem access.",
                    risk_level="L4",
                    confidence=0.8,
                )
            )
        if any(x in joined for x in ["url", "uri", "webhook"]):
            findings.append(
                Finding(
                    id="MCG-SCHEMA-002",
                    title="arbitrary url parameter",
                    severity="medium",
                    category="schema",
                    location=loc,
                    evidence=redact_text(joined[:120]),
                    reason="Schema accepts potentially unbounded URL input.",
                    recommendation="Enforce URL allowlist and egress control.",
                    risk_level="L3",
                    confidence=0.8,
                )
            )
        if any(x in joined for x in ["command", "shell", "script", "exec", "code"]):
            findings.append(
                Finding(
                    id="MCG-SCHEMA-003",
                    title="command/code execution parameter",
                    severity="high",
                    category="schema",
                    location=loc,
                    evidence=redact_text(joined[:120]),
                    reason="Schema may allow code/command execution semantics.",
                    recommendation="Disallow generic command fields and require explicit safe operations.",
                    risk_level="L4",
                    confidence=0.85,
                )
            )
        if node.get("additionalProperties") is True:
            findings.append(
                Finding(
                    id="MCG-SCHEMA-004",
                    title="schema allows additionalProperties",
                    severity="medium",
                    category="schema",
                    location=loc,
                    evidence="additionalProperties=true",
                    reason="Loose schema may hide unreviewed parameters.",
                    recommendation="Set additionalProperties=false unless justified.",
                    risk_level="L2",
                    confidence=0.75,
                )
            )
    return findings
