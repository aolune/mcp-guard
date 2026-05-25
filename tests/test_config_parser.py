from pathlib import Path
from mcp_guard.parsers.config import load_documents, extract_mcp_servers

def test_load_and_extract():
    docs = load_documents(Path("examples/dangerous_stdio_config.json"))
    assert len(docs) == 1
    servers = extract_mcp_servers(docs[0][1])
    assert "evil" in servers
