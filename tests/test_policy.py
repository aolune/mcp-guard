from mcp_guard.policy import apply_policy, policy_fail_on, should_fail
from mcp_guard.scanner import scan_path
from mcp_guard.summary import build_summary


def test_policy_ignore_and_fail():
    result = scan_path("examples/poisoned_tool_manifest.json")
    policy = {"ignore_finding_ids": ["MCG-TOOL-003"], "fail_on": "medium"}
    filtered = apply_policy(result.findings, policy)
    assert all(f.id != "MCG-TOOL-003" for f in filtered)
    assert policy_fail_on(None, policy) == "medium"
    assert should_fail("high", "medium") is True


def test_summary_recomputed_after_filtering():
    result = scan_path("examples/dangerous_stdio_config.json")
    filtered = [f for f in result.findings if f.id != "MCG-CONFIG-004"]
    summary = build_summary(filtered)
    assert summary.credential_review_required is False
