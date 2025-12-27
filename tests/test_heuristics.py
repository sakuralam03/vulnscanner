from src.heuristics import HeuristicsEngine

def test_detect_sqli_error_signature():
    engine = HeuristicsEngine()
    baseline = "<html>OK</html>"
    responses = [("' OR '1'='1", 200, "<html>ORA-00933 error</html>")]
    evidence = engine.detect_sqli("http://example.com", baseline, responses)
    assert any("ORA-" in e for e in evidence)
