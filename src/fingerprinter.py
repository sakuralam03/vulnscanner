import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class Fingerprinter:
    def __init__(self):
        # Evidence store: {endpoint: {headers, cookies, scripts, errors}}
        self.evidence = {}

    def fingerprint(self, url):
        snapshot = {
            "headers": {},
            "cookies": {},
            "scripts": [],
            "errors": []
        }

        try:
            resp = requests.get(url, timeout=5)
        except Exception as e:
            snapshot["errors"].append(f"Request failed: {e}")
            self.evidence[url] = snapshot
            return snapshot

        # --- Headers ---
        for key in ["Server", "X-Powered-By"]:
            if key in resp.headers:
                snapshot["headers"][key] = resp.headers[key]

        # --- Cookies ---
        for cookie in resp.cookies:
            snapshot["cookies"][cookie.name] = {
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": cookie.get_nonstandard_attr("SameSite")
            }

        # --- Script sources ---
        if "text/html" in resp.headers.get("Content-Type", ""):
            soup = BeautifulSoup(resp.text, "html.parser")
            for script in soup.find_all("script", src=True):
                src = urljoin(url, script["src"])
                snapshot["scripts"].append(src)

                # Quick tech hints
                if "react" in src.lower():
                    snapshot["scripts"].append("Hint: React detected")
                if "angular" in src.lower():
                    snapshot["scripts"].append("Hint: Angular detected")
                if "vue" in src.lower():
                    snapshot["scripts"].append("Hint: Vue detected")

        # --- Error signatures ---
        error_signatures = [
            "ORA-", "ODBC", "MySQL", "PostgreSQL", "SQLite",
            "Exception", "Traceback"
        ]
        for sig in error_signatures:
            if sig in resp.text:
                snapshot["errors"].append(f"Signature: {sig}")

        # Store snapshot
        self.evidence[url] = snapshot
        return snapshot

    def report(self):
        """Print evidence store for teaching/demo purposes."""
        for url, snapshot in self.evidence.items():
            print(f"\n[fingerprint] {url}")
            print("Headers:", snapshot["headers"])
            print("Cookies:", snapshot["cookies"])
            print("Scripts:", snapshot["scripts"])
            print("Errors:", snapshot["errors"])


if __name__ == "__main__":
    fp = Fingerprinter()
    fp.fingerprint("http://localhost:8080")
    fp.report()
