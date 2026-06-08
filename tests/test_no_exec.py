import subprocess

from mcp_guard.scanner import scan_path


def test_scan_does_not_execute_configured_stdio_command(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("scanner must not execute configured MCP commands")

    monkeypatch.setattr(subprocess, "Popen", fail_if_called)
    result = scan_path("examples/dangerous_stdio_config.json")
    assert result.findings
