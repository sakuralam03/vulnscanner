🛡️ Vulnerability Scanner Pipeline
A modular, educational vulnerability scanner built to analyze web applications like OWASP Juice Shop. This pipeline discovers endpoints, fingerprints technologies, injects payloads, interprets anomalies, and generates structured reports.

📦 Dependencies
Install all required Python packages:





pip install -r requirements.txt
🧪 Target: OWASP Juice Shop
Run Juice Shop locally using Docker:





# Pull the official image
docker pull bkimminich/juice-shop

# Run it on port 8080
docker run --rm -p 8080:3000 bkimminich/juice-shop
Access it at: http://localhost:8080

🧭 Crawler
Purpose: Discover endpoints, forms, and JavaScript routes.

Uses BFS/DFS to traverse links.

Normalizes URLs and extracts forms.

Builds a list of probe targets (e.g. /rest/products/search?q=).

These targets are passed downstream to the scanner.

Example discovery: /rest/products/search with parameter q.

🕵️ Fingerprinter
Purpose: Collect passive evidence from each endpoint.

1. Headers
Extracts server metadata from resp.headers:





Server: Express
X-Powered-By: Node.js
2. Cookies
Analyzes resp.cookies for security flags:




{
  "token": {
    "secure": false,
    "httponly": true,
    "samesite": "Lax"
  }
}
3. Scripts
Parses HTML for <script src="..."> tags:





<script src="runtime.js"></script>
<script src="main.js"></script>
Infers frontend tech (SPA frameworks like React/Angular/Vue).

4. Error Signatures
Scans resp.text for known backend errors:

ORA-, MySQL, PostgreSQL, SQLite

Exception, Traceback

All evidence is stored as:





self.evidence[url] = {
  "headers": {...},
  "cookies": {...},
  "scripts": [...],
  "errors": [...]
}
🧨 Harness
Purpose: Inject payloads and observe anomalies.

1. Baseline Request
Captures control response for comparison:





baseline_text, baseline_status = get_baseline(url, params)
2. Payload Families
python



SQLI_PAYLOADS = ["' OR '1'='1", "' AND '1'='1", "' OR SLEEP(2)--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\" onmouseover=\"alert(1)", "';alert(1);//"]
3. CSRF Checks
Looks for CSRF tokens and missing headers:

python



check_csrf_tokens(resp.text, resp.headers)
4. Matrix Generation
Builds test cases by injecting payloads into each parameter:





q="' OR '1'='1"
q="<script>alert(1)</script>"
5. Harness Runner
Sends each payload, compares response to baseline:





diff_len = len(resp.text) - len(baseline_text)
print(f"Payload {variant} -> status={resp.status_code}, Δlen={diff_len}")
Includes CSRF hints and throttles time-based payloads.

🧠 Heuristics Engine
Purpose: Interpret anomalies into vulnerability signals.

SQL Injection
Error signature detection

Status code anomalies

Response length diffs

Timing anomalies

XSS
Raw payload reflection

<script> context detection

Event attribute injection

CSRF
Token absence or staleness

Missing Origin/Referer headers

Cookie flags (Secure, SameSite)

📝 Reporter
Purpose: Generate structured findings and artifacts.

Each finding includes:

Endpoint, method, parameters

Request/response excerpts

Fingerprint evidence

Heuristic signals

Risk score (based on exploitability, impact, confidence)

Outputs
reports/findings.json — machine-readable

reports/findings.html — human-readable

Reproducible curl commands

🚀 Example Scan



python src/pipeline.py
This runs the full pipeline against Juice Shop and generates a populated vulnerability report.

🧱 Modular Architecture




Crawler → Fingerprinter → Harness → HeuristicsEngine → Reporter
Each module is standalone, testable, and designed for educational reuse. put it into one copy and pastable block