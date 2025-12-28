import requests
from bs4 import BeautifulSoup
import logging

# --- Setup logging ---
logging.basicConfig(
    filename="logs/audit.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

def log_request(method, url, status):
    logging.info(f"{method} {url} -> {status}")

# --- Target ---
BASE_URL = "http://localhost:8080"

def crawl_homepage():
    print(f"[+] Crawling {BASE_URL}")
    resp = requests.get(BASE_URL)
    log_request("GET", BASE_URL, resp.status_code)

    soup = BeautifulSoup(resp.text, "html.parser")
    links = [a.get("href") for a in soup.find_all("a", href=True)]
    print("[+] Found links:", links)
    return links

def test_payload(url, payload):
    target = f"{BASE_URL}{url}?q={payload}"
    print(f"[+] Testing {target}")
    resp = requests.get(target)
    log_request("GET", target, resp.status_code)
    if payload in resp.text:
        print("[!] Potential reflection detected")
    else:
        print("[+] No reflection")

if __name__ == "__main__":
    links = crawl_homepage()
    if links:
        test_payload(links[0], "<script>alert(1)</script>")
