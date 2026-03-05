from typer.testing import CliRunner

from cli.main import app


runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ai-sec-audit 0.1.0" in result.stdout


def test_scan_command() -> None:
    result = runner.invoke(app, ["scan", "./example-target"])
    assert result.exit_code == 0
    assert "Scanning target: ./example-target" in result.stdout
