import json
import html
from datetime import datetime

class Reporter:
    def __init__(self):
        self.findings = []

    def add_finding(self, endpoint, method, params, request_excerpt,
                    response_excerpt, diffs, timing_stats, confidence,
                    exploitability=1, impact=1):
        """Add a structured finding with metadata."""
        score = self.risk_score(exploitability, impact, confidence)
        finding = {
            "endpoint": endpoint,
            "method": method,
            "params": params,
            "request_excerpt": request_excerpt[:200],   # truncate for readability
            "response_excerpt": response_excerpt[:200],
            "diffs": diffs,
            "timing_stats": timing_stats,
            "confidence": confidence,
            "risk_score": score,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.findings.append(finding)

    def risk_score(self, exploitability, impact, confidence):
        """Simple weighted risk scoring."""
        return exploitability * 0.4 + impact * 0.4 + confidence * 0.2

    # --- Artifact generation ---
    def to_json(self, path="reports/findings.json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=2)
        print(f"[reporter] JSON written to {path}")

    def to_html(self, path="reports/findings.html"):
        html_content = ["<html><head><title>Scan Report</title></head><body>"]
        html_content.append("<h1>Vulnerability Scan Report</h1>")
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
            html_content.append("</details></div>")
        html_content.append("</body></html>")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(html_content))
        print(f"[reporter] HTML written to {path}")

    # --- Reproducible cURL ---
    def generate_curl(self, endpoint, method="GET", params=None, headers=None):
        curl = ["curl"]
        if method == "POST":
            curl.append("-X POST")
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

    # Demo finding
    reporter.add_finding(
        endpoint="http://example.com/search",
        method="GET",
        params={"q": "' OR '1'='1"},
        request_excerpt="GET /search?q=' OR '1'='1'",
        response_excerpt="<html>ORA-00933 error</html>",
        diffs={"length_diff": 120},
        timing_stats={"avg_latency": 0.3, "payload_latency": 2.5},
        confidence=0.9,
        exploitability=3,
        impact=3
    )

    reporter.to_json()
    reporter.to_html()

    curl_cmd = reporter.generate_curl("http://example.com/search", "GET", {"q": "' OR '1'='1"})
    print("\n[repro cURL]\n", curl_cmd)
