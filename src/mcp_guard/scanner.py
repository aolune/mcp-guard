from __future__ import annotations

from pathlib import Path

from mcp_guard.models import ScanResult
from mcp_guard.parsers import extract_mcp_servers, extract_tools, load_documents
from mcp_guard.rules import scan_server, scan_tool
from mcp_guard.standards import annotate_findings
from mcp_guard.summary import build_summary


def scan_path(target: str) -> ScanResult:
    findings = []
    for file, data in load_documents(Path(target)):
        for name, server in extract_mcp_servers(data).items():
            findings.extend(scan_server(name, server, str(file)))
        for tool in extract_tools(data):
            findings.extend(scan_tool(tool, str(file)))
    findings = annotate_findings(findings)
    return ScanResult(target=target, findings=findings, summary=build_summary(findings))
