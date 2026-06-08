from __future__ import annotations

from pathlib import Path

from mcp_guard.models import Finding
from mcp_guard.parsers import extract_tools, load_documents


def _tools(path: str):
    docs = [d for _, d in load_documents(Path(path))]
    out = {}
    for d in docs:
        for t in extract_tools(d):
            out[t.name] = t
    return out


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
        if baseline_tools[n].model_dump() != current_tools[n].model_dump():
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
                    risk_score=65,
                    risk_level="L4",
                    policy_action="require_approval",
                    confidence=0.95,
                )
            )
    return findings
