import requests
import time
import json
from urllib.parse import urlencode

# --- Baseline control request ---
def get_baseline(url, method="GET", params=None, data=None, headers=None):
    """Capture baseline response for diffs."""
    if method == "GET":
        resp = requests.get(url, params=params, headers=headers, timeout=5)
    else:
        resp = requests.post(url, data=data, headers=headers, timeout=5)
    return resp.text, resp.status_code


# --- Payload families ---
SQLI_PAYLOADS = [
    "' OR '1'='1",          # error-based
    "' AND '1'='1",         # boolean-based
    "' OR SLEEP(2)--"       # time-based (⚠ throttle to avoid DoS)
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",   # tag injection
    "\" onmouseover=\"alert(1)",   # attribute context
    "';alert(1);//"                # JS string breakout
]

# CSRF checks are more about observing tokens/headers than injecting payloads
def check_csrf_tokens(resp_text, headers):
    hints = []
    if "csrf" in resp_text.lower():
        hints.append("CSRF token present in page")
    if "Origin" not in headers and "Referer" not in headers:
        hints.append("No Origin/Referer header in baseline")
    return hints


# --- Matrix generation ---
def build_param_matrix(endpoint, params):
    """Generate combinations of params with payloads."""
    matrix = []
    for key in params.keys():
        for payload in SQLI_PAYLOADS + XSS_PAYLOADS:
            new_params = params.copy()
            new_params[key] = payload
            matrix.append(new_params)
    return matrix


# --- Harness runner ---
def run_harness(endpoint, method="GET", params=None, data=None, headers=None):
    print(f"\n[harness] Testing {endpoint} ({method})")

    # Capture baseline
    baseline_text, baseline_status = get_baseline(endpoint, method, params, data, headers)
    print(f"[baseline] status={baseline_status}, length={len(baseline_text)}")

    # Build matrix
    if params:
        matrix = build_param_matrix(endpoint, params)
    elif data:
        matrix = build_param_matrix(endpoint, data)
    else:
        matrix = []

    # Iterate payloads
    for variant in matrix:
        try:
            if method == "GET":
                resp = requests.get(endpoint, params=variant, headers=headers, timeout=5)
            else:
                resp = requests.post(endpoint, data=variant, headers=headers, timeout=5)

            # Compare with baseline
            diff_len = len(resp.text) - len(baseline_text)
            print(f"Payload {variant} -> status={resp.status_code}, Δlen={diff_len}")

            # CSRF hints
            csrf_hints = check_csrf_tokens(resp.text, resp.headers)
            for hint in csrf_hints:
                print(f"  [csrf] {hint}")

            # Throttle for time-based payloads
            time.sleep(1.0)

        except Exception as e:
            print(f"[error] {variant} -> {e}")


if __name__ == "__main__":
    # Example: safe demo endpoint
    test_url = "http://example.com/search"
    test_params = {"q": "test"}

    run_harness(test_url, method="GET", params=test_params)
