import pytest
from src.session import log_request

def test_log_request_creates_entry(tmp_path):
    log_file = tmp_path / "audit.log"
    import logging
    logging.basicConfig(filename=log_file, level=logging.INFO)
    log_request("GET", "http://example.com", 200)
    content = log_file.read_text()
    assert "GET http://example.com -> 200" in content
