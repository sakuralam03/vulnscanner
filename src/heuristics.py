import re
import statistics
import time
from reporter import Reporter   # <-- import Reporter

class HeuristicsEngine:
    def __init__(self):
        self.signals = {}

    def detect_sqli(self, url, baseline, responses, timings=None):
        evidence = []
        error_signatures = ["ORA-", "ODBC", "MySQL", "PostgreSQL", "SQLite", "Exception", "Traceback"]
        for payload, status, body in responses:
            for sig in error_signatures:
                if sig in body:
                    evidence.append(f"SQLi error signature '{sig}' reflected for payload {payload}")
        baseline_len = len(baseline)
        for payload, status, body in responses:
            if status != 200:
                evidence.append(f"Status code anomaly {status} for payload {payload}")
            if abs(len(body) - baseline_len) > 50:
                evidence.append(f"Response length diff for payload {payload}")
        if timings:
            latencies = [lat for _, lat in timings]
            if len(latencies) > 1:
                avg = statistics.mean(latencies)
                for payload, lat in timings:
                    if lat > avg * 2:
                        evidence.append(f"Timing anomaly: payload {payload} took {lat:.2f}s vs avg {avg:.2f}s")
        self.signals[url] = {"SQLi": evidence}
        return evidence

    def detect_xss(self, url, responses):
        evidence = []
        for payload, body in responses:
            if payload in body:
                evidence.append(f"Raw reflection of payload {payload}")
                if re.search(r"<script[^>]*>" + re.escape(payload), body):
                    evidence.append(f"Payload reflected inside <script> context: {payload}")
                if re.search(r"on\w+\s*=\s*['\"]" + re.escape(payload), body):
                    evidence.append(f"Payload reflected inside event attribute: {payload}")
        self.signals[url] = {"XSS": evidence}
        return evidence

    def detect_csrf(self, url, baseline_form, test_form, headers, cookies):
        evidence = []
        if "csrf" not in test_form and "csrf" in baseline_form:
            evidence.append("CSRF token missing in test form")
        elif test_form.get("csrf") == baseline_form.get("csrf"):
            evidence.append("CSRF token not rotated")
        if "Origin" not in headers and "Referer" not in headers:
            evidence.append("State change allowed without Origin/Referer")
        for name, flags in cookies.items():
            if not flags.get("secure"):
                evidence.append(f"Cookie {name} missing Secure flag")
            if not flags.get("samesite"):
                evidence.append(f"Cookie {name} missing SameSite flag")
        self.signals[url] = {"CSRF": evidence}
        return evidence

    def report(self):
        for url, categories in self.signals.items():
            print(f"\n[heuristics] {url}")
            for category, evidence in categories.items():
                print(f" {category}:")
                for e in evidence:
                    print(f"   - {e}")


if __name__ == "__main__":
    engine = HeuristicsEngine()
    reporter = Reporter()

    # Demo: fake baseline + responses
    baseline = "<html>OK</html>"
    sqli_responses = [
        ("' OR '1'='1", 200, "<html>ORA-00933 error</html>"),
        ("' AND '1'='1", 500, "<html>Server error</html>")
    ]
    sqli_timings = [
        ("' OR SLEEP(2)--", 2.5),
        ("' AND '1'='1", 0.3)
    ]
    sqli_evidence = engine.detect_sqli("http://localhost:8080/search", baseline, sqli_responses, sqli_timings)

    xss_responses = [
        ("<script>alert(1)</script>", "<html><body><script>alert(1)</script></body></html>")
    ]
    xss_evidence = engine.detect_xss("http://localhost:8080/profile", xss_responses)

    baseline_form = {"csrf": "abc123"}
    test_form = {"csrf": "abc123"}
    headers = {}
    cookies = {"sessionid": {"secure": False, "samesite": None}}
    csrf_evidence = engine.detect_csrf("http://localhost:8080/update", baseline_form, test_form, headers, cookies)

    engine.report()

    # Build heuristics snapshot
    heuristics_snapshot = {
        "SQLi": sqli_evidence,
        "XSS": xss_evidence,
        "CSRF": csrf_evidence
    }

    # Add a demo finding to reporter
    reporter.add_finding(
        endpoint="http://localhost:8080/search",
        method="GET",
        params={"q": "' OR '1'='1"},
        request_excerpt="GET /search?q=' OR '1'='1'",
        response_excerpt="<html>ORA-00933 error</html>",
        diffs={"length_diff": 120},
        timing_stats={"avg_latency": 0.3, "payload_latency": 2.5},
        confidence=0.9,
        exploitability=3,
        impact=3,
        fingerprint={},  # normally from Fingerprinter
        heuristics=heuristics_snapshot
    )

    reporter.to_json()
    reporter.to_html()
