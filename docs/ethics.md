# Ethics & Guardrails

## Authorization
- Written permission is required before scanning.
- Scope is limited to approved domains and paths.
- Scans must occur only within agreed time windows.

## Safety
- Payloads in `data/payloads/` must be non-destructive.
  - Example SQLi: `' OR '1'='1`
  - Example XSS: `<script>alert(1)</script>`
- Never send POST requests that alter state unless in a sandbox/test environment.

## Logging & Accountability
- Every probe request must be logged in `logs/audit.log`.
- Logs must include timestamp, method, URL, and response status.
- Audit logs are immutable and must not be tampered with.
