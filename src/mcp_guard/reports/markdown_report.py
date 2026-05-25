from mcp_guard.models import ScanResult

def render_markdown(result: ScanResult) -> str:
    s=result.summary
    lines=["# mcp-guard Report", "", f"Target: {result.target}", f"Gate: {s.gate_result.upper()}", f"Max severity: {s.max_severity.upper()}", f"Tool risk level: {s.tool_risk_level}", "", "## Summary", "", f"- Findings: {s.total_findings}", f"- Approval required: {'yes' if s.approval_required else 'no'}", f"- Sandbox required: {'yes' if s.sandbox_required else 'no'}", f"- Egress review required: {'yes' if s.egress_review_required else 'no'}", f"- Credential review required: {'yes' if s.credential_review_required else 'no'}", "", "## Findings", ""]
    for f in result.findings:
        lines += [f"### {f.id} {f.title}", "", f"Severity: {f.severity.upper()}", f"Risk level: {f.risk_level}", f"Location: {f.location}", f"Evidence: {f.evidence}", f"Reason: {f.reason}", f"Recommendation: {f.recommendation}", ""]
    return "\n".join(lines)
