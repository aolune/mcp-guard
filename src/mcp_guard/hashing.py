from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mcp_guard.parsers import load_documents


def canonical_hash(path: str) -> str:
    docs = [d for _, d in load_documents(Path(path))]
    payload = json.dumps(docs, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()
