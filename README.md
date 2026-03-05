# ai-sec-audit

`ai-sec-audit` is a Python-based CLI project scaffold for building an AI-powered security auditing tool.

## Project Structure

- `parser/` — parse source code, logs, or configuration files.
- `scanner/` — run static and semantic security checks.
- `llm/` — integrate LLM-assisted analysis workflows.
- `reporting/` — generate audit reports (JSON, Markdown, SARIF, etc.).
- `models/` — shared domain models and schemas.
- `cli/` — Typer-based command-line interface entrypoints.
- `tests/` — pytest test suite.
- `docs/` — project documentation.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m cli.main --help
pytest
```

## Development

- Use `pytest` for tests.
- Add modules progressively under each package folder.
- Keep the CLI in `cli/main.py` and register commands there.
