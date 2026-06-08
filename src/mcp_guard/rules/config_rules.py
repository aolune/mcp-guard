from __future__ import annotations

import re
from urllib.parse import urlparse

from mcp_guard.models import Finding
from mcp_guard.redaction import redact_secret_value, redact_text

SHELL_LAUNCHERS = {"bash", "sh", "powershell", "pwsh", "cmd"}
SHELL_ARG_PATTERNS = [
    "curl",
    "wget",
    "nc ",
    "ncat",
    "base64",
    "eval",
    "rm -rf",
    "chmod",
    "ssh",
    "scp",
    "python -c",
    "node -e",
    "ruby -e",
    "perl -e",
]
PACKAGE_LAUNCHERS = {"npx", "uvx", "pipx"}
SECRET_NAMES = [
    "API_KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GITHUB_TOKEN",
]
SECRET_VALUE_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{12,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
]


def _finding(**kwargs) -> Finding:
    return Finding(**kwargs)


def _joined_command(command: str, args: list[object]) -> str:
    return " ".join([command, *(str(arg) for arg in args)]).strip()


def _package_is_pinned(package: str) -> bool:
    if not package or package.startswith("-"):
        return True
    if package.startswith("@"):
        return package.count("@") >= 2
    return "@" in package


def _first_package_arg(args: list[object]) -> str:
    for arg in args:
        value = str(arg)
        if value.startswith("-"):
            continue
        return value
    return ""


def _is_private_host(host: str) -> bool:
    return (
        host in {"localhost", "169.254.169.254"}
        or host.startswith("127.")
        or re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", host) is not None
    )


def scan_server(name: str, server: dict, path: str) -> list[Finding]:
    findings: list[Finding] = []
    cmd = str(server.get("command", ""))
    args = server.get("args", [])
    args = args if isinstance(args, list) else []
    env = server.get("env", {})
    transport = str(server.get("transport", ""))
    url = str(server.get("url", ""))
    joined = _joined_command(cmd, args)
    cmd_name = cmd.lower().split("\\")[-1].split("/")[-1]

    if cmd or transport == "stdio":
        findings.append(
            _finding(
                id="MCPG-STDIO-001",
                title="stdio command configured",
                severity="high",
                category="stdio",
                capability="code_exec",
                location=f"{path}.mcpServers.{name}.command",
                evidence=redact_text(joined or "stdio"),
                reason="Local stdio servers expand the execution boundary before tool metadata is trusted.",
                recommendation="Review before connecting; prefer pinned packages and a sandboxed execution profile.",
                risk_score=65,
                risk_level="L3",
                policy_action="require_approval",
                confidence=0.95,
            )
        )

    if cmd_name in PACKAGE_LAUNCHERS:
        package = _first_package_arg(args)
        if not _package_is_pinned(package):
            findings.append(
                _finding(
                    id="MCPG-STDIO-002",
                    title="unpinned package execution",
                    severity="high",
                    category="supply_chain",
                    capability="supply_chain",
                    location=f"{path}.mcpServers.{name}.args",
                    evidence=redact_text(joined),
                    reason="Package launcher command does not pin the MCP server package version or digest.",
                    recommendation="Pin package versions or digests before approving this server.",
                    risk_score=70,
                    risk_level="L3",
                    policy_action="require_approval",
                    confidence=0.9,
                )
            )

    if cmd_name in SHELL_LAUNCHERS or any(pattern in joined.lower() for pattern in SHELL_ARG_PATTERNS):
        findings.append(
            _finding(
                id="MCPG-STDIO-003",
                title="dangerous shell command",
                severity="critical",
                category="stdio",
                capability="shell_exec",
                location=f"{path}.mcpServers.{name}.command",
                evidence=redact_text(joined),
                reason="Shell or command-execution pattern detected in MCP server launch configuration.",
                recommendation="Deny by default, or require explicit approval plus a sandbox and command allowlist.",
                risk_score=90,
                risk_level="L4",
                policy_action="deny",
                confidence=0.95,
            )
        )

    for key, value in env.items() if isinstance(env, dict) else []:
        key_upper = str(key).upper()
        value_text = str(value)
        if any(secret_name in key_upper for secret_name in SECRET_NAMES):
            findings.append(
                _finding(
                    id="MCPG-SECRET-001",
                    title="secret-like environment variable configured",
                    severity="high",
                    category="secret",
                    capability="credential_access",
                    location=f"{path}.mcpServers.{name}.env.{key}",
                    evidence=f"{key}={redact_secret_value(value_text)}",
                    reason="Secret-like environment variable is passed into the MCP server runtime.",
                    recommendation="Use scoped short-lived credentials and avoid passing broad secrets to tools.",
                    risk_score=75,
                    risk_level="L4",
                    policy_action="deny",
                    confidence=0.9,
                )
            )
        if any(pattern.search(value_text) for pattern in SECRET_VALUE_PATTERNS):
            findings.append(
                _finding(
                    id="MCPG-SECRET-002",
                    title="secret-like environment value configured",
                    severity="high",
                    category="secret",
                    capability="credential_access",
                    location=f"{path}.mcpServers.{name}.env.{key}",
                    evidence=f"{key}={redact_secret_value(value_text)}",
                    reason="Environment value resembles a token, key, or signed credential.",
                    recommendation="Rotate exposed test secrets and inject scoped credentials at runtime only.",
                    risk_score=80,
                    risk_level="L4",
                    policy_action="deny",
                    confidence=0.9,
                )
            )

    if not url:
        return findings

    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme != "https":
        findings.append(
            _finding(
                id="MCPG-NET-001",
                title="non-https remote MCP url",
                severity="medium",
                category="config",
                capability="network_fetch",
                location=f"{path}.mcpServers.{name}.url",
                evidence=redact_text(url),
                reason="Remote MCP URL does not use HTTPS.",
                recommendation="Require HTTPS and certificate validation for remote MCP servers.",
                risk_score=35,
                risk_level="L2",
                policy_action="allow_with_constraints",
                confidence=0.9,
            )
        )

    host = (parsed.hostname or "").lower()
    if _is_private_host(host):
        findings.append(
            _finding(
                id="MCPG-NET-002",
                title="localhost/private/metadata MCP url",
                severity="high",
                category="config",
                capability="network_fetch",
                location=f"{path}.mcpServers.{name}.url",
                evidence=redact_text(url),
                reason="Remote MCP URL points to a local, private, or cloud metadata endpoint.",
                recommendation="Block private and metadata endpoints unless explicitly reviewed.",
                risk_score=80,
                risk_level="L4",
                policy_action="deny",
                confidence=0.95,
            )
        )

    return findings
