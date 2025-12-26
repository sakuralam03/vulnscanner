# src/scanner.py
import time
import re
import json
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import requests
from bs4 import BeautifulSoup

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
]

SQLI_ERROR_PAYLOADS = ["'", '"', "')", '")', " or '1'='1", " or '1'='2", ")", "'--", '"--']
SQLI_BOOL_TRUE = "1' AND '1'='1"
SQLI_BOOL_FALSE = "1' AND '1'='2"
SQLI_TIME = "1' OR SLEEP(3)--"

XSS_PAYLOADS = [
    "<xss>", "<img src=x onerror=alert(1)>", "';alert(1);//", '" autofocus onfocus=alert(1) "',
    '"><script>alert(1)</script>'
]

class Scanner:
    def __init__(self, base_url, scope_paths=None, respect_robots=True, timeout=10, rate_delay=0.5):
        self.base_url = base_url.rstrip("/")
        self.base_host = urlparse(self.base_url).netloc
        self.scope_paths = scope_paths or []
        self.respect_robots = respect_robots
        self.timeout = timeout
        self.rate_delay = rate_delay
        self.sess = requests.Session()
        self.sess.headers.update({"User-Agent": USER_AGENTS[0]})
        self.visited = set()
        self.queue = [self.base_url]
        self.findings = []

    def in_scope(self, url):
        u = urlparse(url)
        if u.netloc != self.base_host:
            return False
        path = u.path or "/"
        if not self.scope_paths:
            return True
        return any(path.startswith(p) for p in self.scope_paths)

    def get(self, url):
        time.sleep(self.rate_delay)
        try:
            return self.sess.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def post(self, url, data):
        time.sleep(self.rate_delay)
        try:
            return self.sess.post(url, data=data, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def discover(self, html, base_url):
        soup = BeautifulSoup(html, "html.parser")
        # links
        for a in soup.find_all("a", href=True):
            href = urljoin(base_url, a["href"])
            if self.in_scope(href) and href not in self.visited:
                self.queue.append(href)
        # forms
        forms = []
        for f in soup.find_all("form"):
            action = f.get("action") or base_url
            method = (f.get("method") or "GET").upper()
            target = urljoin(base_url, action)
            inputs = []
            for inp in f.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append(name)
            forms.append({"url": target, "method": method, "params": inputs})
        return forms

    def crawl(self, max_pages=100):
        pages = 0
        forms_catalog = []
        while self.queue and pages < max_pages:
            url = self.queue.pop(0)
            if url in self.visited or not self.in_scope(url):
                continue
            resp = self.get(url)
            if not resp or not resp.ok:
                continue
            self.visited.add(url)
            forms = self.discover(resp.text, url)
            forms_catalog.extend(forms)
            pages += 1
        return forms_catalog

    def build_param_sets(self, form):
        # basic param set: each param gets tested individually
        params = form["params"]
        if not params:
            return []
        return [{p: "test"} for p in params]

    def sqli_probe(self, url, method, base_params):
        # error-based
        for p in base_params:
            for payload in SQLI_ERROR_PAYLOADS:
                params = dict(p)
                k = list(params.keys())[0]
                params[k] = params[k] + payload
                control = self.request(url, method, p)
                test = self.request(url, method, params)
                if not control or not test:
                    continue
                if self.has_sql_error(test.text) or self.response_differs(control, test):
                    self.report("SQLi (error/behavior)", url, method, params, control, test)
        # boolean-based
        for p in base_params:
            k = list(p.keys())[0]
            tparams = dict(p); fparams = dict(p)
            tparams[k] = SQLI_BOOL_TRUE; fparams[k] = SQLI_BOOL_FALSE
            t = self.request(url, method, tparams)
            f = self.request(url, method, fparams)
            if t and f and self.response_differs(t, f, threshold=0.2):
                self.report("SQLi (boolean)", url, method, {"T": tparams, "F": fparams}, t, f)
        # time-based
        for p in base_params:
            k = list(p.keys())[0]
            params = dict(p); params[k] = SQLI_TIME
            start = time.time(); t = self.request(url, method, params); dt = time.time() - start
            c = self.request(url, method, p)
            if t and c and dt - self.avg_latency(c) > 2.5:
                self.report("SQLi (time)", url, method, params, c, t)

    def xss_probe(self, url, method, base_params):
        for p in base_params:
            k = list(p.keys())[0]
            for payload in XSS_PAYLOADS:
                params = dict(p); params[k] = payload
                control = self.request(url, method, p)
                test = self.request(url, method, params)
                if not control or not test:
                    continue
                if payload in test.text and not self.is_html_escaped(test.text, payload):
                    self.report("XSS (reflected)", url, method, params, control, test)

    def csrf_token_check(self, form_html):
        soup = BeautifulSoup(form_html, "html.parser")
        tokens = [i.get("value") for i in soup.find_all("input", {"type": "hidden"}) if "csrf" in (i.get("name","") + i.get("id","")).lower()]
        return {"has_token": bool(tokens), "tokens": tokens}

    def request(self, url, method, params):
        if method == "GET":
            qs = urlencode(params, doseq=True)
            conduit = "&" if urlparse(url).query else "?"
            return self.get(url + conduit + qs)
        else:
            return self.post(url, params)

    def has_sql_error(self, text):
        signatures = ["SQL syntax", "ORA-", "ODBC", "MySQL", "PostgreSQL", "SQLite", "syntax error", "Unhandled exception"]
        t = text.lower()
        return any(s.lower() in t for s in signatures)

    def response_differs(self, r1, r2, threshold=0.1):
        # simple length-based heuristic plus status change
        len1, len2 = len(r1.text), len(r2.text)
        if r1.status_code != r2.status_code:
            return True
        if len1 == 0 or len2 == 0:
            return False
        delta = abs(len1 - len2) / max(len1, len2)
        return delta > threshold

    def avg_latency(self, resp):
        # naive placeholder
        return 0.5

    def is_html_escaped(self, text, payload):
        # crude check: if characters appear HTML-encoded, consider escaped
        enc = (payload
               .replace("<", "&lt;")
               .replace(">", "&gt;")
               .replace('"', "&quot;")
               .replace("'", "&#x27;"))
        return enc in text

    def report(self, kind, url, method, params, control_resp, test_resp):
        item = {
            "type": kind,
            "url": url,
            "method": method,
            "params": params,
            "status_control": control_resp.status_code if control_resp else None,
            "status_test": test_resp.status_code if test_resp else None,
            "len_control": len(control_resp.text) if control_resp else None,
            "len_test": len(test_resp.text) if test_resp else None,
        }
        self.findings.append(item)
        print(f"[!] {kind} at {url} ({method}) -> {params}")

    def run(self, max_pages=50):
        forms = self.crawl(max_pages=max_pages)
        for form in forms:
            url, method = form["url"], form["method"]
            param_sets = self.build_param_sets(form)
            if not param_sets:
                continue
            self.sqli_probe(url, method, param_sets)
            self.xss_probe(url, method, param_sets)
        with open("findings.json", "w") as f:
            json.dump(self.findings, f, indent=2)

if __name__ == "__main__":
    scanner = Scanner(base_url="https://example.com", scope_paths=["/app"])
    scanner.run()
