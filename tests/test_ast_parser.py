import json
from pathlib import Path

from parser.ast_parser import RepositoryAstParser


def test_parse_repository_extracts_functions_classes_and_imports(tmp_path: Path) -> None:
    module = tmp_path / "sample.py"
    module.write_text(
        "\n".join(
            [
                "import os as operating_system",
                "from typing import Any",
                "",
                "class Service(BaseService):",
                "    pass",
                "",
                "def run(value: int) -> str:",
                "    return str(value)",
                "",
                "async def arun(data):",
                "    return data",
            ]
        ),
        encoding="utf-8",
    )

    parser = RepositoryAstParser(tmp_path)
    result = parser.parse()

    assert result["summary"]["python_files"] == 1
    assert result["summary"]["parsed_files"] == 1
    assert result["summary"]["files_with_errors"] == 0

    parsed_file = result["files"][0]
    assert parsed_file["path"] == "sample.py"

    assert [item["name"] for item in parsed_file["classes"]] == ["Service"]
    assert parsed_file["classes"][0]["bases"] == ["BaseService"]

    function_names = [item["name"] for item in parsed_file["functions"]]
    assert function_names == ["run", "arun"]
    assert parsed_file["functions"][0]["returns"] == "str"
    assert parsed_file["functions"][1]["is_async"] is True

    import_modules = [item["module"] for item in parsed_file["imports"]]
    assert import_modules == ["os", "typing"]


def test_parse_repository_handles_syntax_errors(tmp_path: Path) -> None:
    bad_file = tmp_path / "broken.py"
    bad_file.write_text("def missing(:\n    pass\n", encoding="utf-8")

    parser = RepositoryAstParser(tmp_path)
    result = parser.parse()

    assert result["summary"]["files_with_errors"] == 1
    assert result["files"][0]["parse_error"] is not None


def test_to_json_returns_valid_json(tmp_path: Path) -> None:
    module = tmp_path / "mod.py"
    module.write_text("def f():\n    return 1\n", encoding="utf-8")

    parser = RepositoryAstParser(tmp_path)
    parsed = json.loads(parser.to_json())

    assert parsed["summary"]["python_files"] == 1
    assert parsed["files"][0]["functions"][0]["name"] == "f"
