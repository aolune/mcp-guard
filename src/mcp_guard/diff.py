from __future__ import annotations

from pathlib import Path

from mcp_guard.models import Finding
from mcp_guard.parsers import extract_tools, load_documents
from mcp_guard.risk import RISK_ORDER, max_risk_score
from mcp_guard.rules import scan_tool
from mcp_guard.standards import annotate_findings


def _tools(path: str):
    docs = [d for _, d in load_documents(Path(path))]
    out = {}
    for d in docs:
        for t in extract_tools(d):
            out[t.name] = t
    return out


def _tool_findings(tool, source: str) -> list[Finding]:
    return annotate_findings(scan_tool(tool, source))


def _max_risk_level(findings: list[Finding]) -> str:
    return max((finding.risk_level for finding in findings), key=lambda level: RISK_ORDER[level], default="L0")


def _capabilities(findings: list[Finding]) -> set[str]:
    return {finding.capability for finding in findings if finding.capability != "unknown"}


def _primary_capability(capabilities: list[str]) -> str:
    priority = [
        "shell_exec",
        "code_exec",
        "credential_access",
        "network_send",
        "file_write",
        "file_read",
        "overbroad_schema",
    ]
    for capability in priority:
        if capability in capabilities:
            return capability
    return capabilities[0] if capabilities else "supply_chain"


def diff_tools(base: str, current: str) -> list[Finding]:
    baseline_tools = _tools(base)
    current_tools = _tools(current)
    findings: list[Finding] = []

    for n in sorted(current_tools.keys() - baseline_tools.keys()):
        findings.append(
            Finding(
                id="MCPG-SC-003",
                title="tool added",
                severity="medium",
                category="supply_chain",
                capability="supply_chain",
                location=n,
                evidence=n,
                reason="New tool was introduced after baseline.",
                recommendation="Re-run approval workflow for newly added tools.",
                risk_score=45,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.9,
            )
        )

    for n in sorted(baseline_tools.keys() - current_tools.keys()):
        findings.append(
            Finding(
                id="MCPG-SC-004",
                title="tool removed",
                severity="low",
                category="supply_chain",
                capability="supply_chain",
                location=n,
                evidence=n,
                reason="Existing tool removed from current manifest.",
                recommendation="Review removal impact and trust chain.",
                risk_score=15,
                risk_level="L1",
                policy_action="allow",
                confidence=0.9,
            )
        )

    for n in sorted(baseline_tools.keys() & current_tools.keys()):
        baseline_tool = baseline_tools[n]
        current_tool = current_tools[n]
        if baseline_tool.model_dump() != current_tool.model_dump():
            baseline_findings = _tool_findings(baseline_tool, f"{base}.{n}")
            current_findings = _tool_findings(current_tool, f"{current}.{n}")
            baseline_risk = _max_risk_level(baseline_findings)
            current_risk = _max_risk_level(current_findings)
            added_capabilities = sorted(_capabilities(current_findings) - _capabilities(baseline_findings))
            if RISK_ORDER[current_risk] > RISK_ORDER[baseline_risk] or added_capabilities:
                findings.append(
                    Finding(
                        id="MCPG-SC-001",
                        title="capability escalation after baseline",
                        severity="high" if current_risk != "L4" else "critical",
                        category="supply_chain",
                        capability=_primary_capability(added_capabilities),
                        location=n,
                        evidence=", ".join(added_capabilities) or f"{baseline_risk} -> {current_risk}",
                        reason="Tool definition changed in a way that introduces new or higher-risk capabilities.",
                        recommendation="Fail admission and require security re-approval before trusting this tool.",
                        risk_score=max(max_risk_score(current_findings), 75),
                        risk_level=current_risk if current_risk != "L0" else "L3",
                        policy_action="deny" if current_risk == "L4" else "require_approval",
                        confidence=0.95,
                    )
                )
            findings.append(
                Finding(
                    id="MCPG-SC-002",
                    title="tool definition hash changed",
                    severity="high",
                    category="supply_chain",
                    capability="supply_chain",
                    location=n,
                    evidence=n,
                    reason="Tool schema/description changed compared to baseline.",
                    recommendation="Treat as potential rug pull and require security re-review.",
                    risk_score=60,
                    risk_level="L3",
                    policy_action="require_approval",
                    confidence=0.95,
                )
            )
    return annotate_findings(findings)
