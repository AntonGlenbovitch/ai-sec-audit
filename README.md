# ai-sec-audit

`ai-sec-audit` is a Python command-line project for building an AI-assisted security auditing workflow for Python repositories. It combines deterministic static-analysis patterns with an extensible architecture for future LLM-guided triage and reporting.

The repository currently provides a clean scaffold with a working CLI entrypoint, package boundaries, and tests so teams can iterate quickly toward a production-grade security scanning tool.

## Table of Contents

- [Project Description](#project-description)
- [Installation](#installation)
- [Usage Example](#usage-example)
- [Architecture](#architecture)
- [Example Output](#example-output)
- [Future Roadmap](#future-roadmap)
- [Development](#development)

## Project Description

The goal of `ai-sec-audit` is to make secure code reviews more consistent and automatable by:

- Parsing Python code and metadata that can be analyzed programmatically.
- Running scanner logic to identify risky code patterns.
- Enabling LLM-assisted reasoning for contextual validation and severity tuning.
- Producing structured outputs suitable for CI pipelines and human triage.

At this stage, the codebase emphasizes strong foundations: package organization, CLI ergonomics, and testability.

## Installation

### Prerequisites

- Python 3.10+
- `pip`

### Setup

```bash
# 1) Clone the repository
git clone <your-repo-url>
cd ai-sec-audit

# 2) Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# 3) Install dependencies
pip install -r requirements.txt
```

(Optional) Install in editable mode for local development:

```bash
pip install -e .
```

## Usage Example

Show CLI commands:

```bash
python -m cli.main --help
```

Run the example scan command against a local path:

```bash
python -m cli.main scan ./
```

Check the tool version:

```bash
python -m cli.main version
```

## Architecture

`ai-sec-audit` is organized into modular packages to separate concerns and simplify future expansion:

- `cli/` — command-line interface and user interaction.
- `parser/` — parsing logic for source artifacts.
- `scanner/` — security scanning logic and rule execution.
- `llm/` — LLM integration points for assisted analysis.
- `reporting/` — output generation (machine + human-readable).
- `models/` — shared domain models and data contracts.
- `tests/` — automated checks (currently focused on CLI behavior).
- `docs/` — architecture and supporting documentation.

### Current execution flow

```text
CLI command
  -> target selection
  -> scan invocation (placeholder)
  -> user-visible output
```

### Target end-state flow

```text
Target repository
  -> parser
  -> static scanner
  -> LLM-assisted triage
  -> report generator
```

For a deeper architectural outline, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Example Output

Example help output:

```text
$ python -m cli.main --help

 Usage: python -m cli.main [OPTIONS] COMMAND [ARGS]...

 AI security audit CLI

 Commands:
   scan     Placeholder scan command.
   version  Show the current project version.
```

Example scan output:

```text
$ python -m cli.main scan ./
Scanning target: ./
```

## Future Roadmap

Planned improvements include:

1. **Parser expansion**
   - Add robust AST parsing and error-tolerant file ingestion.
2. **Rule engine implementation**
   - Introduce initial security rules (e.g., command injection, weak crypto, insecure deserialization).
3. **LLM orchestration layer**
   - Add optional provider-backed finding triage with structured JSON output.
4. **Reporting formats**
   - Implement JSON, SARIF, and Markdown reports with severity summaries.
5. **CI/CD integration**
   - Support configurable exit codes, baseline comparison, and pipeline-friendly outputs.
6. **Performance and scale**
   - Add caching, parallel processing, and incremental scans for large repositories.

## Development

Run tests:

```bash
pytest
```

Linting/formatting can be added as the project matures (e.g., Ruff, Black, mypy).
