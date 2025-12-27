from src.harness import get_baseline

def test_baseline_response(monkeypatch):
    def fake_get(url, **kwargs):
        class Resp:
            text = "<html>OK</html>"
            status_code = 200
        return Resp()
    monkeypatch.setattr("requests.get", fake_get)
    text, status = get_baseline("http://example.com")
    assert "OK" in text
    assert status == 200
