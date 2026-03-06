from llm.analyzer import SnippetAnalyzer, analyze_snippet


def test_analyze_snippet_detects_eval_usage() -> None:
    result = analyze_snippet("result = eval(user_input)")

    assert result["severity_level"] == "high"
    assert "Dynamic code execution" in result["vulnerability_explanation"]
    assert "Avoid eval/exec" in result["recommended_fix"]


def test_snippet_analyzer_falls_back_for_unknown_pattern() -> None:
    analyzer = SnippetAnalyzer()
    result = analyzer.analyze("print('hello world')")

    assert result.severity_level == "low"
    assert "does not match a known high-confidence pattern" in result.vulnerability_explanation
