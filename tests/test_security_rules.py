from scanner.security_rules import scan_source


def test_scan_source_detects_requested_rules() -> None:
    source = """
import pickle
import subprocess

password = "super-secret"

payload = "2 + 2"
result = eval(payload)
exec("print('hi')")
pickle.loads(b"abc")
subprocess.run("echo hello", shell=True)
"""

    result = scan_source(source, "sample.py")

    assert result["parse_error"] is None
    assert result["summary"]["total"] == 5

    rule_ids = {finding["rule_id"] for finding in result["findings"]}
    assert rule_ids == {
        "PY-EVAL-001",
        "PY-EXEC-001",
        "PY-PICKLE-001",
        "PY-SUBPROCESS-001",
        "PY-SECRET-001",
    }


def test_scan_source_detects_alias_import_patterns() -> None:
    source = """
from pickle import loads as deserialize
import subprocess as sp

api_key = "abc123"
deserialize(b"payload")
sp.Popen("ls", shell=True)
"""
    result = scan_source(source)

    assert result["summary"]["total"] == 3
    assert result["summary"]["by_severity"]["high"] == 2
    assert result["summary"]["by_severity"]["medium"] == 1


def test_scan_source_handles_syntax_error() -> None:
    result = scan_source("def broken(:\n  pass\n", "bad.py")

    assert result["path"] == "bad.py"
    assert result["parse_error"] is not None
    assert result["summary"]["total"] == 0
