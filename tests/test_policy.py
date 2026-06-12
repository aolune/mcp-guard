import pytest

from mcp_guard.policy import PolicyError, apply_policy, policy_fail_on, should_fail, validate_policy
from mcp_guard.scanner import scan_path
from mcp_guard.summary import build_summary


def test_policy_ignore_and_fail():
    result = scan_path("examples/poisoned_tool_manifest.json")
    policy = {"ignore_finding_ids": ["MCPG-INJ-002"], "fail_on": "medium"}
    filtered = apply_policy(result.findings, policy)
    assert all(f.id != "MCPG-INJ-002" for f in filtered)
    assert policy_fail_on(None, policy) == "medium"
    assert should_fail("high", "medium") is True


def test_summary_recomputed_after_filtering():
    result = scan_path("examples/dangerous_stdio_config.json")
    filtered = [f for f in result.findings if f.capability != "credential_access"]
    summary = build_summary(filtered)
    assert summary.credential_review_required is False


def test_policy_denies_capability():
    result = scan_path("examples/arbitrary_file_read_manifest.json")
    policy = {"deny_capabilities": ["file_read"]}
    filtered = apply_policy(result.findings, policy)
    assert any(f.capability == "file_read" and f.policy_action == "deny" for f in filtered)


def test_invalid_policy_values_raise_clear_errors():
    with pytest.raises(PolicyError, match="Unsupported fail_on"):
        validate_policy({"fail_on": "severe"})

    with pytest.raises(PolicyError, match="must be a list of strings"):
        validate_policy({"deny_capabilities": "shell_exec"})

    with pytest.raises(PolicyError, match="Unsupported require_approval_levels"):
        validate_policy({"require_approval_levels": ["L9"]})

    with pytest.raises(PolicyError, match="Unsupported fail_on"):
        should_fail("high", "severe")
