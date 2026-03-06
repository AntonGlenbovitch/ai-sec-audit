# Vulnerable Python Example

This intentionally insecure sample project is meant for testing static analysis and audit tooling.

## Included vulnerabilities

1. **`eval` usage** in `run_expression`.
2. **Hardcoded secret** in `API_SECRET`.
3. **Unsafe subprocess execution** with `shell=True` in `ping_host`.

> Do not use this code in production.
