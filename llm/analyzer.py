"""LLM-style analyzer for turning suspicious code into actionable guidance."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Structured analysis response for a suspicious code snippet."""

    vulnerability_explanation: str
    severity_level: str
    recommended_fix: str


class SnippetAnalyzer:
    """Rule-guided analyzer that mimics an LLM triage response format."""

    _PATTERN_RESPONSES: tuple[tuple[tuple[str, ...], AnalysisResult], ...] = (
        (
            ("eval(", "exec("),
            AnalysisResult(
                vulnerability_explanation=(
                    "Dynamic code execution is present. If user-controlled input reaches "
                    "eval/exec, an attacker can execute arbitrary Python code on the host."
                ),
                severity_level="high",
                recommended_fix=(
                    "Avoid eval/exec for untrusted data. Use safe parsers such as ast.literal_eval "
                    "for literals, and strict allow-lists for permitted operations."
                ),
            ),
        ),
        (
            ("pickle.loads(", "yaml.load("),
            AnalysisResult(
                vulnerability_explanation=(
                    "Unsafe deserialization is detected. Loading untrusted serialized content "
                    "can trigger arbitrary object construction or code execution."
                ),
                severity_level="high",
                recommended_fix=(
                    "Use safe loaders (for example yaml.safe_load), validate input origin, "
                    "and prefer data formats with strict schemas like JSON."
                ),
            ),
        ),
        (
            ("subprocess", "shell=True", "os.system("),
            AnalysisResult(
                vulnerability_explanation=(
                    "A command execution pattern may allow command injection when user input is "
                    "concatenated into shell commands."
                ),
                severity_level="high",
                recommended_fix=(
                    "Use argument lists instead of shell strings, disable shell=True, and sanitize "
                    "or validate all external input."
                ),
            ),
        ),
        (
            ("SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "cursor.execute("),
            AnalysisResult(
                vulnerability_explanation=(
                    "Potential SQL injection pattern found. Building SQL queries with string "
                    "formatting can let attackers alter query logic."
                ),
                severity_level="high",
                recommended_fix=(
                    "Use parameterized queries/prepared statements and avoid directly "
                    "interpolating user-controlled values into SQL strings."
                ),
            ),
        ),
        (
            ("md5(", "sha1("),
            AnalysisResult(
                vulnerability_explanation=(
                    "Weak cryptographic hashing is used. MD5/SHA1 are vulnerable to collisions "
                    "and are unsafe for security-sensitive integrity or password storage."
                ),
                severity_level="medium",
                recommended_fix=(
                    "Use modern cryptographic primitives such as SHA-256/SHA-3 for integrity, "
                    "and bcrypt/scrypt/Argon2 for password hashing."
                ),
            ),
        ),
        (
            ("password", "secret", "api_key", "token"),
            AnalysisResult(
                vulnerability_explanation=(
                    "A hardcoded secret may be present in source code. Embedded credentials can "
                    "be leaked through repository history or logs."
                ),
                severity_level="medium",
                recommended_fix=(
                    "Move secrets to a secure secret manager or environment variables and rotate "
                    "any exposed credentials."
                ),
            ),
        ),
    )

    _DEFAULT_RESPONSE = AnalysisResult(
        vulnerability_explanation=(
            "The snippet appears suspicious but does not match a known high-confidence pattern. "
            "Further context (data flow, input source, and execution path) is needed."
        ),
        severity_level="low",
        recommended_fix=(
            "Perform a focused code review, add input validation and least-privilege controls, "
            "and run static/dynamic security testing for confirmation."
        ),
    )

    def analyze(self, suspicious_code_snippet: str) -> AnalysisResult:
        """Analyze a code snippet and return explanation, severity, and fix guidance."""
        normalized_snippet = suspicious_code_snippet.lower()

        for indicators, response in self._PATTERN_RESPONSES:
            if any(indicator.lower() in normalized_snippet for indicator in indicators):
                return response

        return self._DEFAULT_RESPONSE


def analyze_snippet(suspicious_code_snippet: str) -> dict[str, str]:
    """Convenience API returning dictionary output expected by callers."""
    result = SnippetAnalyzer().analyze(suspicious_code_snippet)
    return asdict(result)
