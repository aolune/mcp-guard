from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from mcp_guard.models import Finding

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
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


def load_policy(policy_path: str | None) -> dict[str, Any]:
    if not policy_path:
        return {}
    path = Path(policy_path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    return data


def apply_policy(findings: list[Finding], policy: dict[str, Any]) -> list[Finding]:
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
    return policy.get("fail_on", default_fail_on)


def should_fail(max_severity: str, fail_on: str | None) -> bool:
    if not fail_on:
        return False
    return SEV_RANK[max_severity] >= SEV_RANK[fail_on]


def render_default_policy() -> str:
    return DEFAULT_POLICY
