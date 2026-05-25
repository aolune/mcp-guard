from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from mcp_guard.models import Finding

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


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
    if not ignored:
        return findings
    return [f for f in findings if f.id not in ignored]


def policy_fail_on(default_fail_on: str | None, policy: dict[str, Any]) -> str | None:
    return policy.get("fail_on", default_fail_on)


def should_fail(max_severity: str, fail_on: str | None) -> bool:
    if not fail_on:
        return False
    return SEV_RANK[max_severity] >= SEV_RANK[fail_on]
