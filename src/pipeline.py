# src/pipeline.py
from fingerprinter import Fingerprinter
from heuristics_engine import HeuristicsEngine
from harness import run_harness   # your harness runner function
from reporter import Reporter

def main():
    url = "http://localhost:8080/rest/products/search"
    params = {"q": "test"}  # baseline query

    # --- Initialize modules ---
    fp = Fingerprinter()
    heuristics = HeuristicsEngine()
    reporter = Reporter()

    # --- Fingerprinting ---
    fingerprint_snapshot = fp.fingerprint("http://localhost:8080")

    # --- Harness run (inject payloads, capture responses/timings) ---
    baseline_text, baseline_status = run_harness(url, method="GET", params=params)

    # For simplicity, assume run_harness returns lists of responses and timings
    responses = [
        ("' OR '1'='1", 200, "<html>ORA-00933 error</html>"),
        ("' AND '1'='1", 500, "<html>Server error</html>")
    ]
    timings = [
        ("' OR SLEEP(2)--", 2.5),
        ("' AND '1'='1", 0.3)
    ]

    # --- Heuristics analysis ---
    heuristics_snapshot = {}
    heuristics_snapshot["SQLi"] = heuristics.detect_sqli(url, baseline_text, responses, timings)
    heuristics_snapshot["XSS"] = heuristics.detect_xss(url, [
        ("<script>alert(1)</script>", "<html><body><script>alert(1)</script></body></html>")
    ])
    heuristics_snapshot["CSRF"] = heuristics.detect_csrf(
        url,
        baseline_form={"csrf": "abc123"},
        test_form={"csrf": "abc123"},
        headers={},
        cookies={"sessionid": {"secure": False, "samesite": None}}
    )

    # Confidence, exploitability, impact can be derived from heuristics signals
    confidence = 0.9 if heuristics_snapshot["SQLi"] else 0.5
    exploitability = 3
    impact = 3

    # --- Reporter: add finding ---
    reporter.add_finding(
        endpoint=url,
        method="GET",
        params={"q": "' OR '1'='1"},
        request_excerpt="GET /rest/products/search?q=' OR '1'='1'",
        response_excerpt="<html>ORA-00933 error</html>",
        diffs={"length_diff": 120},
        timing_stats={"avg_latency": 0.3, "payload_latency": 2.5},
        confidence=confidence,
        exploitability=exploitability,
        impact=impact,
        fingerprint=fingerprint_snapshot,
        heuristics=heuristics_snapshot
    )

    # --- Generate artifacts ---
    reporter.to_json()
    reporter.to_html()

    # --- Print reproducible cURL ---
    curl_cmd = reporter.generate_curl(url, "GET", {"q": "' OR '1'='1"})
    print("\n[repro cURL]\n", curl_cmd)

if __name__ == "__main__":
    main()
