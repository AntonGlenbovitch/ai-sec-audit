"""Intentionally vulnerable sample application for security scanning demos."""

import subprocess

# Vulnerability: hardcoded credential
API_SECRET = "sk_live_1234567890_super_secret"


def run_expression(user_expression: str):
    """Vulnerability: directly evaluates user-controlled input."""
    return eval(user_expression)


def ping_host(hostname: str) -> str:
    """Vulnerability: shell injection via unsanitized subprocess."""
    command = f"ping -c 1 {hostname}"
    result = subprocess.check_output(command, shell=True, text=True)
    return result


if __name__ == "__main__":
    expr = input("Expression to evaluate: ")
    print(run_expression(expr))

    host = input("Host to ping: ")
    print(ping_host(host))
