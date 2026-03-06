import json

from reporting.report_generator import ReportGenerator


def test_report_generator_outputs_console_json_and_markdown() -> None:
    findings = [
        {
            "path": "app/auth.py",
            "line": 12,
            "severity": "high",
            "message": "Use of eval() can execute untrusted code.",
        },
        {
            "path": "app/config.py",
            "line": 4,
            "severity": "medium",
            "message": "Potential hardcoded secret assigned to 'password'.",
        },
    ]

    report = ReportGenerator(findings)

    console_report = report.to_console()
    assert "Security Findings" in console_report
    assert "app/auth.py:12" in console_report
    assert "[HIGH]" in console_report

    json_report = json.loads(report.to_json())
    assert json_report["summary"]["total"] == 2
    assert json_report["summary"]["by_severity"] == {"high": 1, "medium": 1}
    assert json_report["findings"][0]["path"] == "app/auth.py"

    markdown_report = report.to_markdown()
    assert "# Security Audit Report" in markdown_report
    assert "| File | Line | Severity | Explanation |" in markdown_report
    assert "`app/config.py`" in markdown_report


def test_report_generator_handles_empty_findings() -> None:
    report = ReportGenerator([])

    assert report.to_console() == "No findings detected."

    json_report = json.loads(report.to_json())
    assert json_report["summary"]["total"] == 0
    assert json_report["findings"] == []

    assert "No findings detected." in report.to_markdown()
