from mcp_guard.models import Finding

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RISK_ORDER = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4}


def max_severity(findings: list[Finding]) -> str:
    return max((f.severity for f in findings), key=lambda s: SEV_ORDER[s], default="info")


def max_risk(findings: list[Finding]) -> str:
    return max((f.risk_level for f in findings), key=lambda s: RISK_ORDER[s], default="L0")


def gate_from_findings(findings: list[Finding]) -> str:
    sev = max_severity(findings)
    if sev in {"critical", "high"}:
        return "fail"
    if sev == "medium":
        return "warn"
    return "pass"
