from __future__ import annotations
from pathlib import Path
from mcp_guard.models import ScanResult, ScanSummary
from mcp_guard.parsers import load_documents, extract_mcp_servers, extract_tools
from mcp_guard.rules import scan_server, scan_tool
from mcp_guard.risk import max_severity, max_risk, gate_from_findings


def scan_path(target: str) -> ScanResult:
    findings=[]
    for file,data in load_documents(Path(target)):
        for name,server in extract_mcp_servers(data).items():
            findings.extend(scan_server(name, server, str(file)))
        for tool in extract_tools(data):
            findings.extend(scan_tool(tool, str(file)))
    summary=ScanSummary(
        total_findings=len(findings),
        max_severity=max_severity(findings),
        tool_risk_level=max_risk(findings),
        gate_result=gate_from_findings(findings),
        approval_required=any(f.severity in {"high","critical"} for f in findings),
        sandbox_required=any(f.risk_level=="L4" for f in findings),
        egress_review_required=any(f.id in {"MCG-CONFIG-005","MCG-CONFIG-006","MCG-SCHEMA-002"} for f in findings),
        credential_review_required=any(f.id=="MCG-CONFIG-004" for f in findings),
    )
    return ScanResult(target=target, findings=findings, summary=summary)
