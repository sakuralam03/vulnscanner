from src.fingerprinter import Fingerprinter

def test_fingerprint_headers(monkeypatch):
    fp = Fingerprinter()
    # Fake response with headers
    class FakeResp:
        headers = {"Server": "Apache"}
        cookies = []
        text = "<html></html>"
    fp.evidence["http://example.com"] = {"headers": FakeResp.headers}
    assert "Server" in fp.evidence["http://example.com"]["headers"]
