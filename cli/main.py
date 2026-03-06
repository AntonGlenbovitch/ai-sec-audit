"""Typer entrypoint for ai-sec-audit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer

from llm.analyzer import analyze_snippet
from parser.ast_parser import RepositoryAstParser
from reporting.report_generator import ReportGenerator
from scanner.security_rules import scan_source

app = typer.Typer(help="AI security audit CLI")


@app.command()
def version() -> None:
    """Show the current project version."""
    typer.echo("ai-sec-audit 0.1.0")


@app.command()
def scan(repo_path: str = typer.Argument(..., help="Path to the repository to scan.")) -> None:
    """Scan a repository through parser, scanner, LLM reasoning, and reporting stages."""
    target = Path(repo_path).resolve()

    if not target.exists() or not target.is_dir():
        typer.secho(f"Repository path does not exist or is not a directory: {repo_path}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.echo(f"[1/4] Parsing repository: {target}")
    parsed_repo = RepositoryAstParser(target).parse()

    typer.echo("[2/4] Running scanner")
    findings: list[dict[str, Any]] = []
    for file_data in parsed_repo["files"]:
        if file_data.get("parse_error") is not None:
            continue

        relative_path = file_data["path"]
        file_path = target / relative_path
        scan_result = scan_source(file_path.read_text(encoding="utf-8"), source_path=relative_path)
        findings.extend(scan_result["findings"])

    typer.echo("[3/4] Running LLM reasoning")
    enriched_findings: list[dict[str, Any]] = []
    for finding in findings:
        snippet = _line_snippet(target / finding["path"], finding["line"])
        llm_result = analyze_snippet(snippet)
        enriched_findings.append(
            {
                **finding,
                "explanation": llm_result["vulnerability_explanation"],
                "recommended_fix": llm_result["recommended_fix"],
            }
        )

    typer.echo("[4/4] Generating report")
    report = ReportGenerator(enriched_findings)
    typer.echo(report.to_console())

    summary = {
        "parsed_python_files": parsed_repo["summary"]["parsed_files"],
        "files_with_parse_errors": parsed_repo["summary"]["files_with_errors"],
        "total_findings": len(enriched_findings),
    }
    typer.echo(f"Summary: {summary}")


def _line_snippet(file_path: Path, line_number: int) -> str:
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""

    if line_number < 1 or line_number > len(lines):
        return ""

    return lines[line_number - 1].strip()


if __name__ == "__main__":
    app()
