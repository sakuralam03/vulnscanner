# Payloads

This folder stores harmless test payloads used by vulnscanner.

- **SQLi (`sqli.txt`)**: Error/boolean/time‑based probes. Non‑destructive, only trigger differences.
- **XSS (`xss.txt`)**: Reflection probes. Designed to test escaping, not exploit.
- **CSRF (`csrf.txt`)**: Token/header markers for detection, not actual exploits.

⚠️ Ethics:
- Payloads must never alter state or delete data.
- POST requests only allowed in sandbox/test environments.
- Always respect scope and authorization rules.
