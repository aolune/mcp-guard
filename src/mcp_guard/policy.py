from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from mcp_guard.models import Finding

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RISK_LEVELS = {"L0", "L1", "L2", "L3", "L4"}
ACTION_RANK = {
    "allow": 0,
    "allow_with_constraints": 1,
    "require_approval": 2,
    "quarantine": 3,
    "deny": 4,
}

DEFAULT_POLICY = """version: 1
profile: mcp-guard-v0.1
fail_on: high
ignore_finding_ids: []
deny_capabilities:
  - shell_exec
  - code_exec
  - credential_access
  - payment_purchase
require_approval_levels:
  - L3
  - L4
"""


class PolicyError(ValueError):
    pass


def _format_allowed(values: set[str]) -> str:
    return ", ".join(sorted(values))


def _require_string_list(policy: dict[str, Any], key: str) -> list[str]:
    value = policy.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"Policy field {key} must be a list of strings.")
    return value


def validate_fail_on(fail_on: str | None) -> str | None:
    if fail_on is None:
        return None
    if fail_on not in SEV_RANK:
        raise PolicyError(
            f"Unsupported fail_on: {fail_on}. Supported severities: {_format_allowed(set(SEV_RANK))}."
        )
    return fail_on


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    validate_fail_on(policy.get("fail_on"))
    _require_string_list(policy, "ignore_finding_ids")
    _require_string_list(policy, "deny_capabilities")
    require_approval_levels = _require_string_list(policy, "require_approval_levels")
    invalid_levels = sorted(set(require_approval_levels) - RISK_LEVELS)
    if invalid_levels:
        raise PolicyError(
            "Unsupported require_approval_levels: "
            f"{', '.join(invalid_levels)}. Supported levels: {_format_allowed(RISK_LEVELS)}."
        )
    return policy


def load_policy(policy_path: str | None) -> dict[str, Any]:
    if not policy_path:
        return {}
    path = Path(policy_path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    return validate_policy(data)


def apply_policy(findings: list[Finding], policy: dict[str, Any]) -> list[Finding]:
    validate_policy(policy)
    ignored = set(policy.get("ignore_finding_ids", []))
    deny_capabilities = set(policy.get("deny_capabilities", []))
    require_approval_levels = set(policy.get("require_approval_levels", []))
    out = []
    for finding in findings:
        if finding.id in ignored:
            continue
        updated = finding
        if finding.capability in deny_capabilities:
            updated = updated.model_copy(
                update={
                    "severity": "critical" if finding.risk_level == "L4" else "high",
                    "risk_score": max(finding.risk_score, 75),
                    "risk_level": "L4",
                    "policy_action": "deny",
                    "recommendation": (
                        f"{finding.recommendation} Policy denies capability "
                        f"{finding.capability}."
                    ),
                }
            )
        elif finding.risk_level in require_approval_levels and ACTION_RANK[finding.policy_action] < ACTION_RANK[
            "require_approval"
        ]:
            updated = updated.model_copy(update={"policy_action": "require_approval"})
        out.append(updated)
    return out


def policy_fail_on(default_fail_on: str | None, policy: dict[str, Any]) -> str | None:
    return validate_fail_on(policy.get("fail_on", default_fail_on))


def should_fail(max_severity: str, fail_on: str | None) -> bool:
    if not fail_on:
        return False
    validate_fail_on(fail_on)
    return SEV_RANK[max_severity] >= SEV_RANK[fail_on]


def render_default_policy() -> str:
    return DEFAULT_POLICY
