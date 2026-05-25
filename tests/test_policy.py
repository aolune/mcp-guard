from mcp_guard.policy import apply_policy, policy_fail_on, should_fail
from mcp_guard.scanner import scan_path


def test_policy_ignore_and_fail():
    result = scan_path("examples/poisoned_tool_manifest.json")
    policy = {"ignore_finding_ids": ["MCG-TOOL-003"], "fail_on": "medium"}
    filtered = apply_policy(result.findings, policy)
    assert all(f.id != "MCG-TOOL-003" for f in filtered)
    assert policy_fail_on(None, policy) == "medium"
    assert should_fail("high", "medium") is True
