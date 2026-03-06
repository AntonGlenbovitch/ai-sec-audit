from pathlib import Path

from typer.testing import CliRunner

from cli.main import app


runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ai-sec-audit 0.1.0" in result.stdout


def test_scan_command_runs_pipeline(tmp_path: Path) -> None:
    module = tmp_path / "service.py"
    module.write_text(
        "\n".join(
            [
                "import subprocess",
                "password = 's3cr3t'",
                "subprocess.run('echo hi', shell=True)",
            ]
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    assert "[1/4] Parsing repository" in result.stdout
    assert "[2/4] Running scanner" in result.stdout
    assert "[3/4] Running LLM reasoning" in result.stdout
    assert "[4/4] Generating report" in result.stdout
    assert "Security Findings" in result.stdout
    assert "service.py:2" in result.stdout
    assert "service.py:3" in result.stdout
    assert "'total_findings': 2" in result.stdout


def test_scan_command_fails_for_invalid_path() -> None:
    result = runner.invoke(app, ["scan", "./does-not-exist"])

    assert result.exit_code == 1
    assert "Repository path does not exist or is not a directory" in result.stdout
