from __future__ import annotations

import re
from urllib.parse import urlparse

from mcp_guard.models import Finding
from mcp_guard.redaction import redact_secret_value, redact_text

SHELLS = {"bash", "sh", "powershell", "cmd"}
DANGEROUS_ARGS = [
    "curl",
    "wget",
    "nc",
    "base64",
    "eval",
    "rm -rf",
    "chmod",
    "ssh",
    "scp",
    "python -c",
    "node -e",
]
SECRET_NAMES = [
    "API_KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "AWS_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
]


def scan_server(name: str, server: dict, path: str) -> list[Finding]:
    findings: list[Finding] = []
    cmd = str(server.get("command", ""))
    args = server.get("args", [])
    env = server.get("env", {})
    transport = str(server.get("transport", ""))
    url = str(server.get("url", ""))

    if cmd or transport == "stdio":
        findings.append(
            Finding(
                id="MCG-CONFIG-001",
                title="stdio command configured",
                severity="high",
                category="config",
                location=f"{path}.mcpServers.{name}.command",
                evidence=cmd or "stdio",
                reason="Local stdio command expands execution boundary.",
                recommendation="Require approval+sandbox and avoid default enablement.",
                risk_level="L4",
                confidence=0.95,
            )
        )
    if cmd and any(x in cmd.lower() for x in SHELLS):
        findings.append(
            Finding(
                id="MCG-CONFIG-002",
                title="dangerous shell command",
                severity="high",
                category="config",
                location=f"{path}.mcpServers.{name}.command",
                evidence=redact_text(cmd),
                reason="Shell interpreter launcher detected.",
                recommendation="Use fixed binary command with allowlist and sandbox.",
                risk_level="L4",
                confidence=0.95,
            )
        )

    joined = " ".join(str(a) for a in args)
    if any(x in joined.lower() for x in DANGEROUS_ARGS):
        findings.append(
            Finding(
                id="MCG-CONFIG-003",
                title="suspicious command args",
                severity="medium",
                category="config",
                location=f"{path}.mcpServers.{name}.args",
                evidence=redact_text(joined),
                reason="Potentially dangerous command pattern in args.",
                recommendation="Review arg intent and restrict egress/filesystem actions.",
                risk_level="L3",
                confidence=0.85,
            )
        )

    for k, v in env.items() if isinstance(env, dict) else []:
        if any(s in k.upper() for s in SECRET_NAMES):
            findings.append(
                Finding(
                    id="MCG-CONFIG-004",
                    title="secret-like environment variable configured",
                    severity="medium",
                    category="config",
                    location=f"{path}.mcpServers.{name}.env.{k}",
                    evidence=f"{k}={redact_secret_value(str(v))}",
                    reason="Secret-like variable provided to server runtime.",
                    recommendation="Use short-lived credentials and secret manager injection.",
                    risk_level="L4",
                    confidence=0.9,
                )
            )

    if not url:
        return findings

    p = urlparse(url)
    if p.scheme and p.scheme != "https":
        findings.append(
            Finding(
                id="MCG-CONFIG-005",
                title="non-https remote url",
                severity="medium",
                category="config",
                location=f"{path}.mcpServers.{name}.url",
                evidence=redact_text(url),
                reason="Remote MCP URL is not HTTPS.",
                recommendation="Enforce HTTPS and certificate validation.",
                risk_level="L3",
                confidence=0.9,
            )
        )

    host = (p.hostname or "").lower()
    if host in {"localhost", "169.254.169.254"} or host.startswith("127.") or re.match(
        r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)",
        host,
    ):
        findings.append(
            Finding(
                id="MCG-CONFIG-006",
                title="localhost/private/metadata url",
                severity="high",
                category="config",
                location=f"{path}.mcpServers.{name}.url",
                evidence=redact_text(url),
                reason="URL points to private/local/metadata endpoint.",
                recommendation="Block private/metadata endpoints unless explicitly approved.",
                risk_level="L4",
                confidence=0.95,
            )
        )

    return findings
