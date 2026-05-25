import json
from mcp_guard.models import ScanResult

def render_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(), indent=2)
