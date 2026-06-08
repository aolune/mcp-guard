from __future__ import annotations

from mcp_guard.models import ScanResult


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def render_markdown(result: ScanResult) -> str:
    summary = result.summary
    policy = summary.recommended_policy
    lines = [
        "# mcp-guard Report",
        "",
        f"Target: {result.target}",
        f"Gate: {summary.gate_result.upper()}",
        f"Max severity: {summary.max_severity.upper()}",
        f"Risk level: {summary.tool_risk_level}",
        f"Risk score: {summary.risk_score} / 100",
        "",
        "## Recommended policy",
        "",
        f"- Action: {policy.action}",
        f"- Require approval: {_yes_no(policy.require_approval)}",
        f"- Sandbox: {_yes_no(policy.sandbox)}",
        f"- Network: {policy.network}",
        "",
        "## Summary",
        "",
        f"- Findings: {summary.total_findings}",
        f"- Approval required: {_yes_no(summary.approval_required)}",
        f"- Sandbox required: {_yes_no(summary.sandbox_required)}",
        f"- Egress review required: {_yes_no(summary.egress_review_required)}",
        f"- Credential review required: {_yes_no(summary.credential_review_required)}",
        "",
    ]
    if policy.notes:
        lines.append("## Policy notes")
        lines.append("")
        lines.extend(f"- {note}" for note in policy.notes)
        lines.append("")

    lines.extend(["## Findings", ""])
    if not result.findings:
        lines.extend(["No findings.", ""])
        return "\n".join(lines)

    for finding in result.findings:
        lines += [
            f"### {finding.id} {finding.title}",
            "",
            f"Severity: {finding.severity.upper()}",
            f"Capability: {finding.capability}",
            f"Risk level: {finding.risk_level}",
            f"Risk score: {finding.risk_score} / 100",
            f"Policy action: {finding.policy_action}",
            f"Confidence: {finding.confidence:.2f}",
            f"OWASP MCP: {', '.join(finding.owasp) if finding.owasp else 'n/a'}",
            f"Location: {finding.location}",
            f"Evidence: {finding.evidence}",
            "",
            f"Reason: {finding.reason}",
            "",
            f"Recommendation: {finding.recommendation}",
            "",
        ]
    return "\n".join(lines)
