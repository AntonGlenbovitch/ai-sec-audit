"""Report generation utilities for scanner findings."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any


class ReportGenerator:
    """Generate console, JSON, and Markdown reports for security findings."""

    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self, findings: Iterable[Mapping[str, Any]]) -> None:
        self._findings = [dict(item) for item in findings]

    def to_console(self) -> str:
        """Return a human-readable console report."""
        if not self._findings:
            return "No findings detected."

        lines = ["Security Findings", "================="]
        for finding in self._sorted_findings():
            file_path = finding.get("path", "<unknown>")
            line = finding.get("line", "?")
            severity = str(finding.get("severity", "unknown")).upper()
            explanation = finding.get("message") or finding.get("explanation", "No explanation provided.")
            lines.append(f"- [{severity}] {file_path}:{line} - {explanation}")

        return "\n".join(lines)

    def to_json(self, indent: int = 2) -> str:
        """Return findings as a JSON report."""
        payload = {
            "summary": {
                "total": len(self._findings),
                "by_severity": self._severity_counts(),
            },
            "findings": [self._normalize_finding(item) for item in self._sorted_findings()],
        }
        return json.dumps(payload, indent=indent)

    def to_markdown(self) -> str:
        """Return findings as a Markdown report."""
        lines = ["# Security Audit Report", ""]

        if not self._findings:
            lines.append("No findings detected.")
            return "\n".join(lines)

        lines.extend(
            [
                f"- Total findings: **{len(self._findings)}**",
                "- Severity breakdown: " + ", ".join(
                    f"**{severity}**={count}" for severity, count in self._severity_counts().items()
                ),
                "",
                "| File | Line | Severity | Explanation |",
                "|---|---:|---|---|",
            ]
        )

        for finding in self._sorted_findings():
            normalized = self._normalize_finding(finding)
            lines.append(
                f"| `{normalized['path']}` | {normalized['line']} | {normalized['severity']} | {normalized['explanation']} |"
            )

        return "\n".join(lines)

    def _severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self._findings:
            severity = str(finding.get("severity", "unknown")).lower()
            counts[severity] = counts.get(severity, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: self._severity_order(item[0])))

    def _sorted_findings(self) -> list[dict[str, Any]]:
        findings = [self._normalize_finding(item) for item in self._findings]
        return sorted(findings, key=lambda item: (self._severity_order(item["severity"]), item["path"], item["line"]))

    def _severity_order(self, severity: str) -> int:
        return self._SEVERITY_ORDER.get(severity.lower(), 99)

    def _normalize_finding(self, finding: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "path": str(finding.get("path", "<unknown>")),
            "line": int(finding.get("line", 0)),
            "severity": str(finding.get("severity", "unknown")).lower(),
            "explanation": str(finding.get("message") or finding.get("explanation") or "No explanation provided."),
        }
