# AGENTS.md

## How to run tests
- `uv run pytest`
- `python -m pytest`

## How to run lint
- `uv run ruff check .`

## How to run CLI locally
- `uv run python -m mcp_guard scan examples/dangerous_stdio_config.json`

## Security constraints
- Never execute scanned MCP commands during tests or implementation.
- Never print secret values.
- No network access in tests.

## Coding style
- Small pure functions.
- Deterministic rules.
- Explainable findings.
- Preserve static-first design.
