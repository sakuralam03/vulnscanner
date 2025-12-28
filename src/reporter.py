import json
import html
import os
from datetime import datetime, timezone
from fingerprinter import Fingerprinter
from heuristics_engine import HeuristicsEngine
from harness import run_harness
class Reporter:
    def __init__(self):
        self.findings = []

    def add_finding(self, endpoint, method, params, request_excerpt,
                    response_excerpt, diffs, timing_stats, confidence,
                    exploitability=1, impact=1, fingerprint=None, heuristics=None):
        """Add a structured finding with metadata, fingerprint, and heuristic evidence."""
        score = self.risk_score(exploitability, impact, confidence)
        finding = {
            "endpoint": endpoint,
            "method": method,
            "params": params,
            "request_excerpt": (request_excerpt or "")[:200],
            "response_excerpt": (response_excerpt or "")[:200],
            "diffs": diffs or {},
            "timing_stats": timing_stats or {},
            "confidence": confidence,
            "risk_score": score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "fingerprint": fingerprint or {},
            "heuristics": heuristics or {}
        }
        self.findings.append(finding)

    def risk_score(self, exploitability, impact, confidence):
        """Simple weighted risk scoring."""
        return exploitability * 0.4 + impact * 0.4 + confidence * 0.2

    def to_json(self, path="reports/findings.json"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=2)
        print(f"[reporter] JSON written to {path}")

    def to_html(self, path="reports/findings.html"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        html_content = ["<html><head><title>Scan Report</title></head><body>"]
        html_content.append("<h1>Vulnerability Scan Report</h1>")

        if not self.findings:
            html_content.append("<p>No findings recorded. Call add_finding(...) before generating artifacts.</p>")
        else:
            for f in self.findings:
                html_content.append("<div style='border:1px solid #ccc; margin:10px; padding:10px;'>")
                html_content.append(f"<h2>{html.escape(f['endpoint'])} ({f['method']})</h2>")
                html_content.append(f"<p><b>Risk Score:</b> {f['risk_score']:.2f}</p>")
                html_content.append("<details><summary>Evidence</summary>")
                html_content.append(f"<p><b>Params:</b> {html.escape(str(f['params']))}</p>")
                html_content.append(f"<p><b>Request Excerpt:</b><br><pre>{html.escape(f['request_excerpt'])}</pre></p>")
                html_content.append(f"<p><b>Response Excerpt:</b><br><pre>{html.escape(f['response_excerpt'])}</pre></p>")
                html_content.append(f"<p><b>Diffs:</b> {html.escape(str(f['diffs']))}</p>")
                html_content.append(f"<p><b>Timing Stats:</b> {html.escape(str(f['timing_stats']))}</p>")
                html_content.append(f"<p><b>Confidence:</b> {f['confidence']}</p>")

                if f.get("fingerprint"):
                    fp = f["fingerprint"]
                    html_content.append("<h3>Fingerprint Evidence</h3>")
                    html_content.append(f"<p><b>Headers:</b> {html.escape(str(fp.get('headers', {})))}</p>")
                    html_content.append(f"<p><b>Cookies:</b> {html.escape(str(fp.get('cookies', {})))}</p>")
                    html_content.append(f"<p><b>Scripts:</b> {html.escape(str(fp.get('scripts', [])))}</p>")
                    html_content.append(f"<p><b>Errors:</b> {html.escape(str(fp.get('errors', [])))}</p>")

                if f.get("heuristics"):
                    html_content.append("<h3>Heuristic Evidence</h3>")
                    for category, evidence in f["heuristics"].items():
                        html_content.append(f"<p><b>{html.escape(category)}:</b></p><ul>")
                        for e in evidence:
                            html_content.append(f"<li>{html.escape(e)}</li>")
                        html_content.append("</ul>")

                html_content.append("</details></div>")

        html_content.append("</body></html>")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(html_content))
        print(f"[reporter] HTML written to {path}")

    def generate_curl(self, endpoint, method="GET", params=None, headers=None):
        curl = ["curl"]
        method = (method or "GET").upper()
        if method == "POST":
            curl.append("-X POST")
        elif method not in ("GET", "POST"):
            curl.append(f"-X {method}")

        if headers:
            for k, v in headers.items():
                curl.append(f"-H \"{k}: {v}\"")

        if params:
            if method == "GET":
                query = "&".join(f"{k}={v}" for k, v in params.items())
                curl.append(f"\"{endpoint}?{query}\"")
            else:
                data = "&".join(f"{k}={v}" for k, v in params.items())
                curl.append(f"-d \"{data}\" \"{endpoint}\"")
        else:
            curl.append(f"\"{endpoint}\"")
        return " ".join(curl)

if __name__ == "__main__":
    reporter = Reporter()

    # Example integration
    fp = Fingerprinter()
    fingerprint_snapshot = fp.fingerprint("http://localhost:8080")

    baseline_text, baseline_status, responses, timings = run_harness(
        "http://localhost:8080/rest/products/search",
        params={"q": "test"}
    )

    heuristics = HeuristicsEngine()
    heuristics_snapshot = {
        "SQLi": heuristics.detect_sqli("http://localhost:8080/rest/products/search",
                                       baseline_text, responses, timings)
    }

    reporter.add_finding(
        endpoint="http://localhost:8080/rest/products/search",
        method="GET",
        params={"q": "' OR '1'='1"},
        request_excerpt="GET /rest/products/search?q=' OR '1'='1'",
        response_excerpt=responses[0][2][:200],
        diffs={"length_diff": len(responses[0][2]) - len(baseline_text)},
        timing_stats={"avg_latency": sum(lat for _, lat in timings)/len(timings),
                      "payload_latency": timings[0][1]},
        confidence=0.9,
        exploitability=3,
        impact=3,
        fingerprint=fingerprint_snapshot,
        heuristics=heuristics_snapshot
    )

    reporter.to_json()
    reporter.to_html()
