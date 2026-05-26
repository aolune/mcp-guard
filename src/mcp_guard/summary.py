from __future__ import annotations

from mcp_guard.models import Finding, ScanSummary
from mcp_guard.risk import gate_from_findings, max_risk, max_severity


def build_summary(findings: list[Finding]) -> ScanSummary:
    return ScanSummary(
        total_findings=len(findings),
        max_severity=max_severity(findings),
        tool_risk_level=max_risk(findings),
        gate_result=gate_from_findings(findings),
        approval_required=any(f.severity in {"high", "critical"} for f in findings),
        sandbox_required=any(f.risk_level == "L4" for f in findings),
        egress_review_required=any(
            f.id in {"MCG-CONFIG-005", "MCG-CONFIG-006", "MCG-SCHEMA-002"} for f in findings
        ),
        credential_review_required=any(f.id == "MCG-CONFIG-004" for f in findings),
    )
