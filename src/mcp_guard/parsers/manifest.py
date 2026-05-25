from __future__ import annotations
from typing import Any
from mcp_guard.models import ToolDefinition


def extract_tools(data: dict[str, Any]) -> list[ToolDefinition]:
    raw = data.get("tools")
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if isinstance(item, dict) and item.get("name"):
            out.append(ToolDefinition(name=str(item["name"]), description=str(item.get("description", "")), inputSchema=item.get("inputSchema", {}) or {}))
    return out
