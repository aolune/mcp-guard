from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


class ParseError(ValueError):
    pass


def load_documents(path: Path) -> list[tuple[Path, dict[str, Any]]]:
    if not path.exists():
        raise ParseError(f"Scan path does not exist: {path}")

    if path.is_file():
        files = [path]
    else:
        files = [
            p
            for p in path.rglob("*")
            if p.suffix.lower() in {".json", ".yaml", ".yml"} or p.name.lower() == "readme.md"
        ]
    docs = []
    for file in files:
        text = file.read_text(encoding="utf-8")
        if file.suffix.lower() == ".md":
            data = {
                "tools": [
                    {
                        "name": file.stem,
                        "description": text,
                        "inputSchema": {},
                        "source_type": "markdown",
                    }
                ]
            }
        else:
            try:
                data = json.loads(text) if file.suffix.lower() == ".json" else yaml.safe_load(text)
            except (json.JSONDecodeError, yaml.YAMLError) as exc:
                raise ParseError(f"Failed to parse {file}: {exc}") from exc
        if isinstance(data, dict):
            docs.append((file, data))
    return docs


def extract_mcp_servers(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    servers = data.get("mcpServers") or {}
    return servers if isinstance(servers, dict) else {}
