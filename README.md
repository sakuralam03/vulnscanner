## dependencies 
install requiremnets from requirements.txt
pip install -r requirements.txt


## Regarding the site tested 
 OWASP Juice Shop

 Used docker to install and run it locally 
 ### Pull the official image
docker pull bkimminich/juice-shop

### Run it on port 8080
docker run --rm -p 8080:3000 bkimminich/juice-shop

## Crawler
 discovers endpoints, forms, and JS routes.

Example: /rest/products/search with input q.

This code crawls a site using BFS/DFS, normalizes URLs, and discovers links, forms, and JS routes.

It builds a list of probe targets (forms + routes).

These targets are passed downstream to the vulnscanner pipeline.

In the final report, findings like “SQLi at /rest/products/search” are only possible because the crawler first discovered that endpoint and its q parameter.
## Fingerprinter
1. Headers
When the scanner does resp = requests.get(url), the server sends back HTTP response headers.

Example:

Code


HTTP/1.1 200 OK
Server: Express
Content-Type: text/html
The Fingerprinter looks for keys like Server and X-Powered-By in resp.headers.

That’s how it learned the backend is Express.js.

2. Cookies
The server may set cookies in the response (Set-Cookie header).

The requests library parses them into resp.cookies.

The Fingerprinter checks attributes:

secure → whether cookie is flagged for HTTPS only.

httponly → whether JavaScript can access it.

samesite → whether it restricts cross‑site requests.

That’s how it reported:





{'token': {'secure': False, 'httponly': True, 'samesite': 'Lax'}}
3. Scripts
If the response is HTML (Content-Type: text/html), the scanner parses it with BeautifulSoup.

It searches for <script src="..."> tags.

Each script URL is collected and normalized with urljoin.

Filenames like runtime.js, polyfills.js, vendor.js, main.js are typical of Angular/React/Vue build pipelines.

That’s how the scanner inferred the frontend is a single‑page application (SPA).

4. Errors
The scanner scans the response body (resp.text) for known error signatures:

Database errors: ORA-, MySQL, PostgreSQL, SQLite.

Stack traces: Exception, Traceback.

In your case, none of these strings appeared in the homepage response, so Errors: [].

How It’s Tracked
All this evidence is stored in a snapshot dictionary for each URL:




self.evidence[url] = {
    "headers": {...},
    "cookies": {...},
    "scripts": [...],
    "errors": [...]
}
Later, the Reporter module merges this fingerprint evidence with vulnerability findings (like SQLi or XSS) to produce the final report.


## Harness 
1. Baseline Request




def get_baseline(url, method="GET", params=None, data=None, headers=None):
    ...
    return resp.text, resp.status_code
Sends a normal request (no payloads).

Captures the response body and status code.

This is the control sample used for comparison later.

2. Payload Families




SQLI_PAYLOADS = ["' OR '1'='1", "' AND '1'='1", "' OR SLEEP(2)--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\" onmouseover=\"alert(1)", "';alert(1);//"]
Defines harmless test payloads for SQL Injection and XSS.

These are injected into parameters to see if the server behaves differently.

⚠️ Note: the time‑based SQLi payload (SLEEP(2)) is throttled to avoid DoS.

3. CSRF Checks



def check_csrf_tokens(resp_text, headers):
    if "csrf" in resp_text.lower(): ...
    if "Origin" not in headers and "Referer" not in headers: ...
Looks for CSRF tokens in the HTML.

Checks if Origin/Referer headers are present.

Adds hints about CSRF protection posture.

4. Matrix Generation




def build_param_matrix(endpoint, params):
    for key in params.keys():
        for payload in SQLI_PAYLOADS + XSS_PAYLOADS:
            new_params = params.copy()
            new_params[key] = payload
            matrix.append(new_params)
Builds a test matrix: for each parameter, substitute each payload.

Example: if q=test, it generates:

q="' OR '1'='1"

q="<script>alert(1)</script>"

etc.

5. Harness Runner




def run_harness(endpoint, method="GET", params=None, ...):
    baseline_text, baseline_status = get_baseline(...)
    ...
    for variant in matrix:
        resp = requests.get(endpoint, params=variant, ...)
        diff_len = len(resp.text) - len(baseline_text)
        print(f"Payload {variant} -> status={resp.status_code}, Δlen={diff_len}")
Prints baseline status and length.

Iterates through payload variants.

Sends requests with each payload.

Compares response length to baseline (Δlen).

Prints anomalies (status changes, length differences).

Runs CSRF checks.

Sleeps briefly to avoid hammering the server.

6. Main Block




test_url = "http://localhost:8080/rest/products/search"
test_params = {"q": "test"}
run_harness(test_url, method="GET", params=test_params)
Targets the Juice Shop search endpoint.

Baseline query: q=test.

Harness injects payloads into q and observes differences.