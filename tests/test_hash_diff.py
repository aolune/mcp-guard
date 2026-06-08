from mcp_guard.hashing import canonical_hash
from mcp_guard.diff import diff_tools
from mcp_guard.summary import build_summary

def test_hash_and_diff():
    assert canonical_hash("examples/rug_pull_baseline.json")
    f=diff_tools("examples/rug_pull_baseline.json","examples/rug_pull_changed.json")
    ids={x.id for x in f}
    assert "MCPG-SC-001" in ids
    assert "MCPG-SC-002" in ids
    assert "MCPG-SC-003" in ids


def test_diff_marks_added_capability():
    findings = diff_tools("examples/rug_pull_baseline.json", "examples/rug_pull_changed.json")
    escalation = next(f for f in findings if f.id == "MCPG-SC-001")
    assert "network_send" in escalation.evidence
    assert escalation.capability == "network_send"
    assert escalation.policy_action == "require_approval"
    assert escalation.owasp
    assert build_summary(findings).egress_review_required is True
