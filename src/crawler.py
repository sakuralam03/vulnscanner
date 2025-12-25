import requests
import time
import re
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode
from collections import deque
from bs4 import BeautifulSoup

class Crawler:
    def __init__(self, base_url, mode="BFS", max_depth=3, max_pages=50, delay=1.0):
        self.base_url = base_url
        self.mode = mode  # "BFS" or "DFS"
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay = delay

        self.visited = set()
        self.queue = deque([(base_url, 0)])  # (url, depth)
        self.discovered_forms = []
        self.discovered_js_routes = []

    def normalize_url(self, url):
        """Canonicalize URL and sort query params for deduplication."""
        parsed = urlparse(url)
        params = sorted(parse_qsl(parsed.query))
        normalized_query = urlencode(params)
        normalized = parsed._replace(query=normalized_query).geturl()
        return normalized

    def crawl(self):
        pages_crawled = 0

        while self.queue and pages_crawled < self.max_pages:
            if self.mode == "DFS":
                url, depth = self.queue.pop()
            else:  # BFS
                url, depth = self.queue.popleft()

            if depth > self.max_depth:
                continue

            normalized = self.normalize_url(url)
            if normalized in self.visited:
                continue

            self.visited.add(normalized)
            print(f"[crawl] Visiting: {normalized} (depth={depth})")

            try:
                resp = requests.get(url, timeout=5)
                pages_crawled += 1
                time.sleep(self.delay)
            except Exception as e:
                print(f"[error] {url} -> {e}")
                continue

            if "text/html" in resp.headers.get("Content-Type", ""):
                self.parse_html(resp.text, url, depth)

    def parse_html(self, html, base_url, depth):
        soup = BeautifulSoup(html, "html.parser")

        # Discover links
        for tag in soup.find_all("a", href=True):
            new_url = urljoin(base_url, tag["href"])
            self.queue.append((new_url, depth + 1))

        # Canonical/meta refresh
        for tag in soup.find_all("link", rel="canonical"):
            new_url = urljoin(base_url, tag.get("href"))
            self.queue.append((new_url, depth + 1))
        for tag in soup.find_all("meta", attrs={"http-equiv": "refresh"}):
            content = tag.get("content", "")
            if "url=" in content.lower():
                new_url = urljoin(base_url, content.split("url=")[-1])
                self.queue.append((new_url, depth + 1))

        # Discover forms
        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action", ""))
            method = form.get("method", "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "select", "textarea"]):
                inputs.append(inp.get("name"))
            self.discovered_forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })

        # Discover JS routes (regex scan)
        js_routes = re.findall(r"(?:fetch|xhr|ajax)\(['\"](.*?)['\"]", html, re.IGNORECASE)
        for route in js_routes:
            new_url = urljoin(base_url, route)
            self.discovered_js_routes.append(new_url)
            self.queue.append((new_url, depth + 1))

if __name__ == "__main__":
    crawler = Crawler("http://example.com", mode="BFS", max_depth=2, max_pages=10, delay=0.5)
    crawler.crawl()

    print("\n[forms discovered]")
    for f in crawler.discovered_forms:
        print(f)

    print("\n[js routes discovered]")
    for r in crawler.discovered_js_routes:
        print(r)
