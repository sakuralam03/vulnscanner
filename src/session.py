import logging
import requests

# Configure logging
logging.basicConfig(
    filename="logs/audit.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

def log_request(method, url, status):
    logging.info(f"{method} {url} -> {status}")

def safe_get(url, **kwargs):
    """Wrapper around requests.get with logging."""
    try:
        response = requests.get(url, **kwargs)
        log_request("GET", url, response.status_code)
        return response
    except Exception as e:
        log_request("GET", url, f"ERROR: {e}")
        raise

def safe_post(url, **kwargs):
    """POST requests only allowed in sandbox/test environments."""
    if not kwargs.get("sandbox", False):
        raise PermissionError("POST requests disabled outside sandbox/test environment")
    try:
        response = requests.post(url, **kwargs)
        log_request("POST", url, response.status_code)
        return response
    except Exception as e:
        log_request("POST", url, f"ERROR: {e}")
        raise
