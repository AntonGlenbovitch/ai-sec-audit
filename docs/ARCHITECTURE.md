# ai-sec-audit Architecture

## 1) Overview

`ai-sec-audit` is a Python CLI tool that scans Python repositories for security weaknesses by combining deterministic static analysis with LLM-assisted reasoning.

Core pipeline:

```text
Target repository
  -> AST parser
  -> Static security scanner
  -> LLM reasoning
  -> Report generation
```

Design goals:
- **Security-first defaults**: prioritize high-confidence, actionable findings.
- **Determinism + intelligence**: use rule-based analysis for precision, LLM for contextual triage.
- **Offline-friendly baseline**: static analysis should work without network/LLM.
- **Reproducibility**: track scan inputs, versions, and model metadata.
- **Extensibility**: pluggable rules, parsers, LLM providers, and output formats.

---

## 2) High-Level Architecture

### 2.1 Component Diagram

```text
+----------------------+      +-----------------------+
| CLI / Config Loader |----->| Repository Enumerator |
+----------------------+      +-----------+-----------+
                                        |
                                        v
                              +-----------------------+
                              | AST Parsing Engine    |
                              | (per .py file/module) |
                              +-----------+-----------+
                                          |
                                          v
                              +-----------------------+
                              | Static Scanner        |
                              | - Rule engine         |
                              | - Dataflow helpers    |
                              +-----------+-----------+
                                          |
                                          v
                              +-----------------------+
                              | LLM Reasoning Layer   |
                              | - Prompt builder      |
                              | - Finding triage      |
                              | - Severity tuning     |
                              +-----------+-----------+
                                          |
                                          v
                              +-----------------------+
                              | Report Generator      |
                              | (JSON/SARIF/Markdown) |
                              +-----------------------+
```

### 2.2 Processing Stages

1. **Repository ingestion**
   - Resolve repository path.
   - Apply include/exclude patterns.
   - Build file inventory and scan context.

2. **AST parsing**
   - Parse each candidate Python file to AST.
   - Collect syntax errors as non-fatal diagnostics.
   - Extract symbol table and lightweight metadata.

3. **Static security scanning**
   - Run security rules against AST + metadata.
   - Emit candidate findings with evidence and confidence.
   - Optionally run taint-style heuristics for sources/sinks.

4. **LLM reasoning**
   - Batch candidate findings into prompts with code snippets.
   - Ask LLM to validate exploitability, reduce false positives, and refine severity.
   - Return structured rationale and remediation guidance.

5. **Report generation**
   - Merge static + LLM outputs into normalized findings.
   - Generate machine-readable and human-readable reports.
   - Provide summary metrics and exit-code policy.

---

## 3) Folder Structure

```text
ai-sec-audit/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── RULES.md
│   ├── PROMPTS.md
│   └── REPORT_SCHEMA.md
├── src/
│   └── ai_sec_audit/
│       ├── __init__.py
│       ├── cli/
│       │   ├── main.py
│       │   ├── commands/
│       │   │   ├── scan.py
│       │   │   ├── rules.py
│       │   │   └── config.py
│       │   └── output.py
│       ├── config/
│       │   ├── models.py
│       │   ├── loader.py
│       │   └── defaults.py
│       ├── repo/
│       │   ├── discover.py
│       │   ├── filters.py
│       │   └── snapshot.py
│       ├── parser/
│       │   ├── ast_engine.py
│       │   ├── symbols.py
│       │   └── errors.py
│       ├── scanner/
│       │   ├── engine.py
│       │   ├── findings.py
│       │   ├── severity.py
│       │   ├── rules/
│       │   │   ├── base.py
│       │   │   ├── insecure_deserialization.py
│       │   │   ├── command_injection.py
│       │   │   ├── sql_injection.py
│       │   │   └── weak_crypto.py
│       │   └── dataflow/
│       │       ├── taint.py
│       │       └── sinks_sources.py
│       ├── llm/
│       │   ├── orchestrator.py
│       │   ├── prompt_builder.py
│       │   ├── schemas.py
│       │   ├── providers/
│       │   │   ├── base.py
│       │   │   ├── openai_provider.py
│       │   │   └── local_provider.py
│       │   └── guardrails.py
│       ├── reporting/
│       │   ├── normalize.py
│       │   ├── json_report.py
│       │   ├── markdown_report.py
│       │   ├── sarif_report.py
│       │   └── summary.py
│       ├── cache/
│       │   ├── artifact_store.py
│       │   └── fingerprints.py
│       ├── telemetry/
│       │   ├── logging.py
│       │   └── metrics.py
│       └── utils/
│           ├── paths.py
│           ├── hashing.py
│           └── concurrency.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── pyproject.toml
├── README.md
└── .ai-sec-audit.toml
```

---

## 4) Module Responsibilities

### 4.1 CLI Layer (`cli/`)
- Parse command-line arguments and user config.
- Select scan mode (static-only vs static+LLM).
- Control output format, verbosity, and exit behavior.

### 4.2 Configuration (`config/`)
- Merge defaults, config file, and CLI overrides.
- Validate settings (paths, enabled rules, provider options).
- Provide immutable runtime config objects.

### 4.3 Repository Layer (`repo/`)
- Discover Python files and module boundaries.
- Apply exclusions (`venv`, `.git`, `build`, generated code).
- Create a scan snapshot with file hashes for reproducibility.

### 4.4 Parser Layer (`parser/`)
- Parse source into Python AST (`ast` module).
- Normalize AST metadata for scanner consumption.
- Capture parse errors without crashing full scan.

### 4.5 Scanner Layer (`scanner/`)
- Execute rule registry over parsed modules.
- Produce finding candidates with:
  - rule id
  - location
  - evidence snippet
  - confidence score
  - CWE mapping (if applicable)
- Optional dataflow/taint tracking for source-to-sink patterns.

### 4.6 LLM Layer (`llm/`)
- Enrich or triage findings from static scanner.
- Build bounded prompts with only necessary code context.
- Enforce structured output schema (JSON).
- Add guardrails:
  - no secret exfiltration
  - token budget limits
  - deterministic prompt templates
  - fallback on provider failure

### 4.7 Reporting Layer (`reporting/`)
- Normalize final findings and deduplicate overlaps.
- Emit:
  - JSON (internal API + automation)
  - SARIF (CI/code scanning tools)
  - Markdown (human review)
- Include scan metadata (tool version, ruleset hash, model info).

### 4.8 Cache & Telemetry (`cache/`, `telemetry/`)
- Cache intermediate artifacts (AST fingerprints, prompt/responses where allowed).
- Track runtime stats (files scanned, rules fired, duration).
- Support debug logs and performance tracing.

---

## 5) Data Contracts

### 5.1 Core Finding Model

Each finding should include:
- `id`: stable UUID/hash
- `rule_id`: static scanner rule identifier
- `title`
- `description`
- `severity`: `critical | high | medium | low | info`
- `confidence`: numeric or enum
- `location`: file, line, column, end_line
- `evidence`: code snippet and explanation
- `cwe`: optional
- `owasp`: optional
- `llm_assessment`: optional structured section
- `remediation`: actionable recommendation

### 5.2 LLM Assessment Schema

- `verdict`: `confirm | likely_false_positive | needs_review`
- `reasoning_summary`
- `exploitability_notes`
- `adjusted_severity` (optional)
- `remediation_advice`

---

## 6) Dependency List

Below is a pragmatic dependency plan for initial implementation.

### 6.1 Runtime Dependencies
- **CLI & config**
  - `typer` (CLI ergonomics)
  - `pydantic` (typed config and schemas)
  - `tomli` / `tomllib` (TOML config loading; version-dependent)

- **Parsing & analysis**
  - Python stdlib `ast` (primary parser)
  - `networkx` (optional control/dataflow graph modeling)

- **Reporting**
  - `jinja2` (templated Markdown/HTML reports)
  - `orjson` (fast JSON serialization, optional)

- **LLM integration**
  - `openai` (if OpenAI provider is used)
  - optional local-provider client (e.g., HTTP-based via `httpx`)
  - `tenacity` (retry/backoff for provider calls)

- **Utilities**
  - `rich` (console output)
  - `pathspec` (gitignore-style file filtering)

### 6.2 Development Dependencies
- `pytest`, `pytest-cov` (testing)
- `ruff` (linting + formatting)
- `mypy` (type checking)
- `pre-commit` (developer workflow)

### 6.3 Optional Integrations
- `sarif-om` or custom serializer for SARIF emission
- `sqlite` (stdlib) for persistent cache/indexing

---

## 7) CLI Interface Design

### 7.1 Primary Command

```bash
ai-sec-audit scan [PATH] [OPTIONS]
```

### 7.2 Suggested Commands

1. `scan`
   - Run repository scan.

2. `rules list`
   - List available security rules.

3. `rules describe <RULE_ID>`
   - Show rule details, examples, and references.

4. `config init`
   - Generate `.ai-sec-audit.toml` with defaults.

5. `report convert`
   - Convert JSON results to other formats (e.g., SARIF/Markdown).

### 7.3 `scan` Options

- `--config PATH` : config file path.
- `--include PATTERN` : include glob(s).
- `--exclude PATTERN` : exclude glob(s).
- `--rule RULE_ID` : run only selected rule(s).
- `--severity [low|medium|high|critical]` : minimum severity threshold.
- `--format [json|sarif|md]` : output format.
- `--output PATH` : write report file.
- `--llm-mode [off|assist|required]` : LLM usage policy.
- `--llm-provider [openai|local]` : provider selector.
- `--max-files N` : cap scanned files.
- `--fail-on [none|low|medium|high|critical]` : CI exit-code gating.
- `--baseline PATH` : suppress unchanged historical findings.
- `--verbose` / `--quiet` : logging level control.

### 7.4 Exit Code Policy

- `0`: scan completed, threshold not exceeded.
- `1`: scan completed, findings meet/exceed fail threshold.
- `2`: runtime/config error.

---

## 8) End-to-End Flow (Detailed)

1. CLI parses args and loads effective config.
2. Repository enumerator builds candidate file list.
3. Parser converts files into AST + parse diagnostics.
4. Scanner executes rules and emits raw findings.
5. Findings are deduplicated and ranked.
6. If enabled, LLM triages findings and annotates results.
7. Reporter emits selected formats and summary table.
8. CLI prints final metrics and exits with policy-based status.

---

## 9) Security & Reliability Considerations

- Never execute repository code during scanning.
- Constrain LLM context to least necessary snippets.
- Redact likely secrets before outbound LLM calls.
- Keep deterministic static results as source of truth.
- Record model/provider/version for auditability.
- Provide `--llm-mode off` for fully offline or sensitive environments.

---

## 10) Future Extensions

- Inter-file and inter-procedural taint tracking.
- Plugin API for custom enterprise rules.
- Incremental scanning in CI using git diff.
- IDE integration (LSP diagnostics output).
- Auto-fix suggestions with patch previews.
