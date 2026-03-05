"""AST-based repository parser for Python source files."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any


class RepositoryAstParser:
    """Parse Python repositories and extract structural metadata."""

    def __init__(self, root_path: str | Path) -> None:
        self.root_path = Path(root_path).resolve()

    def parse(self) -> dict[str, Any]:
        """Walk the repository and return parsed data for each Python file."""
        files: list[dict[str, Any]] = []

        for path in sorted(self.root_path.rglob("*.py")):
            if path.is_file():
                files.append(self._parse_file(path))

        return {
            "repository": str(self.root_path),
            "files": files,
            "summary": {
                "python_files": len(files),
                "parsed_files": sum(1 for file_data in files if file_data.get("parse_error") is None),
                "files_with_errors": sum(1 for file_data in files if file_data.get("parse_error") is not None),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Return parsed repository metadata as a JSON string."""
        return json.dumps(self.parse(), indent=indent)

    def _parse_file(self, path: Path) -> dict[str, Any]:
        relative_path = str(path.relative_to(self.root_path))
        source = path.read_text(encoding="utf-8")

        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return {
                "path": relative_path,
                "functions": [],
                "classes": [],
                "imports": [],
                "parse_error": {
                    "message": str(exc),
                    "line": exc.lineno,
                    "column": exc.offset,
                },
            }

        extractor = _ModuleStructureExtractor()
        extractor.visit(tree)

        return {
            "path": relative_path,
            "functions": extractor.functions,
            "classes": extractor.classes,
            "imports": extractor.imports,
            "parse_error": None,
        }


class _ModuleStructureExtractor(ast.NodeVisitor):
    """Extract top-level module structure from an AST tree."""

    def __init__(self) -> None:
        self.functions: list[dict[str, Any]] = []
        self.classes: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(
            {
                "name": node.name,
                "line": node.lineno,
                "args": [arg.arg for arg in node.args.args],
                "returns": ast.unparse(node.returns) if node.returns else None,
                "is_async": False,
            }
        )
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions.append(
            {
                "name": node.name,
                "line": node.lineno,
                "args": [arg.arg for arg in node.args.args],
                "returns": ast.unparse(node.returns) if node.returns else None,
                "is_async": True,
            }
        )
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.classes.append(
            {
                "name": node.name,
                "line": node.lineno,
                "bases": [ast.unparse(base) for base in node.bases],
                "decorators": [ast.unparse(decorator) for decorator in node.decorator_list],
            }
        )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(
                {
                    "type": "import",
                    "module": alias.name,
                    "alias": alias.asname,
                    "line": node.lineno,
                }
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self.imports.append(
                {
                    "type": "from_import",
                    "module": node.module,
                    "name": alias.name,
                    "alias": alias.asname,
                    "level": node.level,
                    "line": node.lineno,
                }
            )
