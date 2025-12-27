from src.reporter import Reporter

def test_add_finding_and_json(tmp_path):
    reporter = Reporter()
    reporter.add_finding(
        endpoint="http://example.com",
        method="GET",
        params={"q": "test"},
        request_excerpt="GET /search?q=test",
        response_excerpt="<html>OK</html>",
        diffs={},
        timing_stats={},
        confidence=0.8,
        exploitability=2,
        impact=2
    )
    path = tmp_path / "findings.json"
    reporter.to_json(path)
    content = path.read_text()
    assert "http://example.com" in content
