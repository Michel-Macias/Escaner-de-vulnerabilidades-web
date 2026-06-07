import pytest
from src.core.extractor import FormExtractor
from src.core.crawler import Crawler
import asyncio


def test_form_extractor():
    html = """
    <html>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username" value="admin">
                <input type="password" name="password">
            </form>
        </body>
    </html>
    """
    extractor = FormExtractor()
    forms = extractor.extract_forms(html, "http://example.com")

    assert len(forms) == 1
    assert forms[0]["action"] == "http://example.com/login"
    assert forms[0]["method"] == "post"
    assert len(forms[0]["inputs"]) == 2
    assert forms[0]["inputs"][0]["name"] == "username"
    assert forms[0]["inputs"][0]["value"] == "admin"


def test_link_extractor():
    html = """
    <html>
        <a href="/page1">Page 1</a>
        <a href="http://example.com/page2">Page 2</a>
        <a href="http://google.com">External</a>
    </html>
    """
    extractor = FormExtractor()
    links = extractor.extract_links(html, "http://example.com")

    assert "http://example.com/page1" in links
    assert "http://example.com/page2" in links
    assert "http://google.com" in links


def test_crawler_limits_and_validation():
    crawler = Crawler("http://example.com", max_urls=10, max_depth=1)
    assert crawler.target_url == "http://example.com"
    assert crawler.domain == "example.com"
    assert crawler.is_valid_url("http://example.com/test")
    assert not crawler.is_valid_url("http://google.com")
    assert crawler.max_urls == 10
    assert crawler.max_depth == 1
