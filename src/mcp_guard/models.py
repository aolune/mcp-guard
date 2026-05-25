from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
RiskLevel = Literal["L0", "L1", "L2", "L3", "L4"]

class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    location: str
    evidence: str
    reason: str
    recommendation: str
    risk_level: RiskLevel
    confidence: float = Field(ge=0, le=1)

class ToolDefinition(BaseModel):
    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=dict)

class ScanSummary(BaseModel):
    total_findings: int
    max_severity: Severity
    tool_risk_level: RiskLevel
    gate_result: Literal["pass", "warn", "fail"]
    approval_required: bool
    sandbox_required: bool
    egress_review_required: bool
    credential_review_required: bool

class ScanResult(BaseModel):
    target: str
    findings: list[Finding]
    summary: ScanSummary
