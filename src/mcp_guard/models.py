from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
RiskLevel = Literal["L0", "L1", "L2", "L3", "L4"]
PolicyAction = Literal[
    "allow",
    "allow_with_constraints",
    "require_approval",
    "deny",
    "quarantine",
]


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    capability: str = "unknown"
    location: str
    evidence: str
    reason: str
    recommendation: str
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: RiskLevel
    policy_action: PolicyAction = "allow_with_constraints"
    confidence: float = Field(ge=0, le=1)
    owasp: list[str] = Field(default_factory=list)


class ToolDefinition(BaseModel):
    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=dict)
    source_type: Literal["manifest", "markdown"] = "manifest"


class PolicyDecision(BaseModel):
    action: PolicyAction
    require_approval: bool = False
    sandbox: bool = False
    network: Literal["allow", "restricted", "deny"] = "allow"
    notes: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    total_findings: int
    max_severity: Severity
    risk_score: int
    tool_risk_level: RiskLevel
    gate_result: Literal["pass", "warn", "fail"]
    approval_required: bool
    sandbox_required: bool
    egress_review_required: bool
    credential_review_required: bool
    recommended_policy: PolicyDecision


class ScanResult(BaseModel):
    target: str
    findings: list[Finding]
    summary: ScanSummary
