# Vulnscanner Architecture

This document explains the design of the vulnscanner project.  
It is intended as a teaching artifact to help learners understand how the modules fit together.

---

## 🎯 Design Goals
- **Ethical scanning**: Respect authorization, scope, and safety guardrails.
- **Modularity**: Each step of the pipeline is isolated in its own module.
- **Reproducibility**: Findings are logged, reported, and reproducible via cURL.
- **Teaching clarity**: Contrast BFS vs DFS, instance vs static methods, safe vs unsafe payloads.

---

## 📂 Module Overview

| Module            | Responsibility                                                                 |
|-------------------|--------------------------------------------------------------------------------|
| `crawler.py`      | Crawl target site, collect URLs and forms. BFS by default, DFS for teaching contrast. |
| `session.py`      | Manage HTTP sessions, cookies, headers, and audit logging.                     |
| `fingerprinter.py`| Identify technologies/frameworks via headers, cookies, script sources, error signatures. |
| `harness.py`      | Core engine to run probes with payload families (SQLi, XSS, CSRF).             |
| `heuristics.py`   | Detection logic: interpret signals (errors, diffs, timing, reflection).        |
| `reporter.py`     | Output results: JSON (machine-readable), HTML (human-readable), cURL repro, risk scoring. |
| `scanner.py`      | Orchestrator: ties all modules together into an end-to-end workflow.           |

---

## 🔄 Data Flow

1. **Crawler** discovers endpoints and forms.
2. **Fingerprinter** collects tech hints (headers, cookies, scripts).
3. **Harness** generates parameter matrices and injects safe payloads.
4. **Heuristics** analyzes responses for detection signals.
5. **Reporter** produces reproducible evidence (JSON, HTML, cURL).
6. **Scanner** coordinates the pipeline and enforces ethics guardrails.

---

## 🛡️ Ethics & Guardrails
- Written permission required before scanning.
- Scope limited to approved domains/paths.
- Payloads stored in `data/payloads/` are **non-destructive**.
- POST requests only allowed in sandbox/test environments.
- All requests logged in `logs/audit.log`.

---

## 📊 Teaching Contrasts
- **Crawler**: BFS vs DFS traversal.
- **Harness**: Control vs payload requests (baseline diffs).
- **Heuristics**: Error-based vs boolean-based vs time-based SQLi.
- **Reporter**: Machine-readable JSON vs human-readable HTML.

---

## 📌 Example Workflow
```text
scanner.py
 ├── crawler.py → forms discovered
 ├── fingerprinter.py → tech hints
 ├── harness.py → probes run
 ├── heuristics.py → signals detected
 └── reporter.py → findings exported
