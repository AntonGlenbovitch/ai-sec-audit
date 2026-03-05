"""Typer entrypoint for ai-sec-audit."""

import typer

app = typer.Typer(help="AI security audit CLI")


@app.command()
def version() -> None:
    """Show the current project version."""
    typer.echo("ai-sec-audit 0.1.0")


@app.command()
def scan(target: str = typer.Argument(..., help="Path or URL to scan.")) -> None:
    """Placeholder scan command."""
    typer.echo(f"Scanning target: {target}")


if __name__ == "__main__":
    app()
