from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import yaml


def load_documents(path: Path) -> list[tuple[Path, dict[str, Any]]]:
    files = [path] if path.is_file() else [p for p in path.rglob("*") if p.suffix.lower() in {".json", ".yaml", ".yml"}]
    docs = []
    for file in files:
        text = file.read_text(encoding="utf-8")
        data = json.loads(text) if file.suffix.lower() == ".json" else yaml.safe_load(text)
        if isinstance(data, dict):
            docs.append((file, data))
    return docs


def extract_mcp_servers(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    servers = data.get("mcpServers") or {}
    return servers if isinstance(servers, dict) else {}
