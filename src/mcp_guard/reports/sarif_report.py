from __future__ import annotations

import json
from typing import Any

from mcp_guard.models import ScanResult

LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _sarif_result(scan: ScanResult, finding) -> dict[str, Any]:
    uri = scan.target.replace("\\", "/")
    return {
        "ruleId": finding.id,
        "level": LEVEL_MAP.get(finding.severity, "warning"),
        "message": {
            "text": (
                f"{finding.title}. Reason: {finding.reason} "
                f"Recommendation: {finding.recommendation}"
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"snippet": {"text": finding.location}},
                }
            }
        ],
        "properties": {
            "category": finding.category,
            "capability": finding.capability,
            "evidence": finding.evidence,
            "risk_score": finding.risk_score,
            "risk_level": finding.risk_level,
            "policy_action": finding.policy_action,
            "confidence": finding.confidence,
            "tags": finding.owasp,
        },
    }


def render_sarif(result: ScanResult) -> str:
    rules = []
    seen = set()
    for finding in result.findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        rules.append(
            {
                "id": finding.id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.reason},
                "help": {"text": finding.recommendation},
                "properties": {
                    "category": finding.category,
                    "risk_level": finding.risk_level,
                    "tags": finding.owasp,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "mcp-guard", "rules": rules}},
                "results": [_sarif_result(result, f) for f in result.findings],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "gate_result": result.summary.gate_result,
                            "max_severity": result.summary.max_severity,
                            "risk_score": result.summary.risk_score,
                            "tool_risk_level": result.summary.tool_risk_level,
                            "recommended_policy": result.summary.recommended_policy.model_dump(),
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)
