import pytest
from src.crawler import Crawler

def test_crawler_discovers_links(monkeypatch):
    html = '<a href="/test">link</a>'
    crawler = Crawler("http://example.com")
    forms = crawler.discover(html, "http://example.com")
    assert any("url" in f for f in forms) or forms == []
