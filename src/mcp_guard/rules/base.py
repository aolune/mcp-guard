from __future__ import annotations
from mcp_guard.models import Finding

def mk_finding(**kwargs) -> Finding:
    return Finding(**kwargs)
