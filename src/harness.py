import requests
import time
from urllib.parse import urlencode
from reporter import Reporter   # <-- import your Reporter class

# --- Baseline control request ---
def get_baseline(url, method="GET", params=None, data=None, headers=None):
    if method == "GET":
        resp = requests.get(url, params=params, headers=headers, timeout=5)
    else:
        resp = requests.post(url, data=data, headers=headers, timeout=5)
    return resp.text, resp.status_code

SQLI_PAYLOADS = ["' OR '1'='1", "' AND '1'='1", "' OR SLEEP(2)--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\" onmouseover=\"alert(1)", "';alert(1);//"]

def check_csrf_tokens(resp_text, headers):
    hints = []
    if "csrf" in resp_text.lower():
        hints.append("CSRF token present in page")
    if "Origin" not in headers and "Referer" not in headers:
        hints.append("No Origin/Referer header in baseline")
    return hints

def build_param_matrix(params):
    matrix = []
    for key in params.keys():
        for payload in SQLI_PAYLOADS + XSS_PAYLOADS:
            new_params = params.copy()
            new_params[key] = payload
            matrix.append(new_params)
    return matrix

def run_harness(endpoint, method="GET", params=None, data=None, headers=None, reporter=None):
    print(f"\n[harness] Testing {endpoint} ({method})")

    baseline_text, baseline_status = get_baseline(endpoint, method, params, data, headers)
    print(f"[baseline] status={baseline_status}, length={len(baseline_text)}")

    matrix = build_param_matrix(params or data or {})

    for variant in matrix:
        try:
            if method == "GET":
                resp = requests.get(endpoint, params=variant, headers=headers, timeout=5)
                request_excerpt = f"GET {endpoint}?{urlencode(variant)}"
            else:
                resp = requests.post(endpoint, data=variant, headers=headers, timeout=5)
                request_excerpt = f"POST {endpoint} body={variant}"

            diff_len = len(resp.text) - len(baseline_text)
            print(f"Payload {variant} -> status={resp.status_code}, Δlen={diff_len}")

            csrf_hints = check_csrf_tokens(resp.text, resp.headers)

            heuristics_snapshot = {}
            if csrf_hints:
                heuristics_snapshot["CSRF"] = csrf_hints
            if "ORA-" in resp.text:
                heuristics_snapshot.setdefault("SQLi", []).append("Oracle error signature detected")

            # Add finding to reporter
            if reporter:
                reporter.add_finding(
                    endpoint=endpoint,
                    method=method,
                    params=variant,
                    request_excerpt=request_excerpt,
                    response_excerpt=resp.text[:200],
                    diffs={"length_diff": diff_len},
                    timing_stats={"payload_latency": resp.elapsed.total_seconds()},
                    confidence=0.9 if heuristics_snapshot else 0.3,
                    exploitability=3,
                    impact=3,
                    fingerprint={},  # normally from Fingerprinter
                    heuristics=heuristics_snapshot
                )

            time.sleep(1.0)

        except Exception as e:
            print(f"[error] {variant} -> {e}")

if __name__ == "__main__":
    test_url = "http://localhost:8080/rest/products/search"
    test_params = {"q": "test"}

    reporter = Reporter()
    run_harness(test_url, method="GET", params=test_params, reporter=reporter)

    reporter.to_json()
    reporter.to_html()
