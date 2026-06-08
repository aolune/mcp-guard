from mcp_guard.hashing import canonical_hash
from mcp_guard.diff import diff_tools

def test_hash_and_diff():
    assert canonical_hash("examples/rug_pull_baseline.json")
    f=diff_tools("examples/rug_pull_baseline.json","examples/rug_pull_changed.json")
    ids={x.id for x in f}
    assert "MCPG-SC-002" in ids and "MCPG-SC-003" in ids
