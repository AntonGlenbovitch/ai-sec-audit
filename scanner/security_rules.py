"""AST-based security rule scanner for Python code."""

from __future__ import annotations

import ast
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Finding:
    """A single security finding emitted by the scanner."""

    rule_id: str
    severity: str
    message: str
    path: str
    line: int
    column: int


class SecurityRuleScanner(ast.NodeVisitor):
    """Visit Python AST nodes and emit findings for insecure patterns."""

    SECRET_NAME_PATTERN = re.compile(
        r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)",
        re.IGNORECASE,
    )

    def __init__(self, source_path: str = "<memory>") -> None:
        self.source_path = source_path
        self.findings: list[Finding] = []
        self._import_aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self._import_aliases[alias.asname] = alias.name
            else:
                root = alias.name.split(".", 1)[0]
                self._import_aliases[root] = root
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.module:
            return

        module_root = node.module.split(".", 1)[0]
        for alias in node.names:
            local_name = alias.asname or alias.name
            self._import_aliases[local_name] = f"{module_root}.{alias.name}"
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._resolve_call_name(node.func)

        if call_name in {"eval", "builtins.eval"}:
            self._add_finding(
                rule_id="PY-EVAL-001",
                severity="high",
                message="Use of eval() can execute untrusted code.",
                node=node,
            )
        elif call_name in {"exec", "builtins.exec"}:
            self._add_finding(
                rule_id="PY-EXEC-001",
                severity="high",
                message="Use of exec() can execute untrusted code.",
                node=node,
            )
        elif call_name in {"pickle.loads", "loads"} and self._is_pickle_loads(call_name, node.func):
            self._add_finding(
                rule_id="PY-PICKLE-001",
                severity="high",
                message="pickle.loads() can deserialize untrusted data and lead to code execution.",
                node=node,
            )

        if self._is_subprocess_shell_true(node):
            self._add_finding(
                rule_id="PY-SUBPROCESS-001",
                severity="high",
                message="subprocess call with shell=True may allow command injection.",
                node=node,
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_hardcoded_secret(node.targets, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_hardcoded_secret([node.target], node.value, node)
        self.generic_visit(node)

    def _check_hardcoded_secret(
        self,
        targets: list[ast.expr],
        value: ast.expr | None,
        node: ast.Assign | ast.AnnAssign,
    ) -> None:
        if value is None or not self._is_hardcoded_literal(value):
            return

        for target in targets:
            if isinstance(target, ast.Name) and self.SECRET_NAME_PATTERN.search(target.id):
                self._add_finding(
                    rule_id="PY-SECRET-001",
                    severity="medium",
                    message=f"Potential hardcoded secret assigned to '{target.id}'.",
                    node=node,
                )

    def _is_hardcoded_literal(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (str, bytes)) and bool(node.value)

        if isinstance(node, ast.JoinedStr):
            return True

        return False

    def _resolve_call_name(self, func: ast.expr) -> str:
        if isinstance(func, ast.Name):
            return self._import_aliases.get(func.id, func.id)

        if isinstance(func, ast.Attribute):
            owner = self._resolve_call_name(func.value)
            if owner:
                return f"{owner}.{func.attr}"
            return func.attr

        return ""

    def _is_pickle_loads(self, call_name: str, func: ast.expr) -> bool:
        if call_name == "pickle.loads":
            return True

        if isinstance(func, ast.Name):
            resolved = self._import_aliases.get(func.id, "")
            return resolved == "pickle.loads"

        return False

    def _is_subprocess_shell_true(self, node: ast.Call) -> bool:
        call_name = self._resolve_call_name(node.func)
        if not call_name.startswith("subprocess."):
            return False

        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                return True

        return False

    def _add_finding(self, rule_id: str, severity: str, message: str, node: ast.AST) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                path=self.source_path,
                line=getattr(node, "lineno", 1),
                column=getattr(node, "col_offset", 0),
            )
        )


def scan_source(source: str, source_path: str = "<memory>") -> dict[str, Any]:
    """Scan Python source code and return structured findings."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {
            "path": source_path,
            "findings": [],
            "summary": {"total": 0, "by_severity": {}},
            "parse_error": {
                "message": str(exc),
                "line": exc.lineno,
                "column": exc.offset,
            },
        }

    scanner = SecurityRuleScanner(source_path)
    scanner.visit(tree)

    findings = [asdict(item) for item in scanner.findings]
    by_severity: dict[str, int] = {}
    for finding in findings:
        sev = finding["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "path": source_path,
        "findings": findings,
        "summary": {"total": len(findings), "by_severity": by_severity},
        "parse_error": None,
    }


def scan_file(path: str | Path) -> dict[str, Any]:
    """Scan a Python file and return structured findings."""
    file_path = Path(path)
    source = file_path.read_text(encoding="utf-8")
    return scan_source(source, str(file_path))


def to_json(result: dict[str, Any], indent: int = 2) -> str:
    """Serialize a scanner result dictionary as JSON."""
    return json.dumps(result, indent=indent)
