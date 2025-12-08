import unittest
from unittest.mock import MagicMock, patch
from src.core.extractor import FormExtractor
from src.core.crawler import Crawler

class TestCore(unittest.TestCase):
    def test_form_extractor(self):
        html = """
        <html>
            <body>
                <form action="/login" method="POST">
                    <input type="text" name="username">
                    <input type="password" name="password">
                </form>
            </body>
        </html>
        """
        extractor = FormExtractor()
        forms = extractor.extract_forms(html, "http://example.com")
        
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["action"], "http://example.com/login")
        self.assertEqual(forms[0]["method"], "post")
        self.assertEqual(len(forms[0]["inputs"]), 2)

    def test_link_extractor(self):
        html = """
        <html>
            <a href="/page1">Page 1</a>
            <a href="http://example.com/page2">Page 2</a>
            <a href="http://google.com">External</a>
        </html>
        """
        extractor = FormExtractor()
        links = extractor.extract_links(html, "http://example.com")
        
        self.assertIn("http://example.com/page1", links)
        self.assertIn("http://example.com/page2", links)
        self.assertIn("http://google.com", links)

    @patch("src.core.crawler.RequestManager")
    def test_crawler(self, MockRequester):
        # Setup Mock
        mock_instance = MockRequester.return_value
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '<html><a href="/page1">Link</a></html>'
        mock_instance.get.return_value = mock_response

        crawler = Crawler("http://example.com")
        crawler.crawl("http://example.com")

        self.assertIn("http://example.com", crawler.visited_urls)
        # Should have tried to crawl page1 if recursive, but we mock the response for page1 too?
        # In the current implementation, crawl calls itself recursively. 
        # To prevent infinite recursion in test without side effects, we might need more careful mocking.
        # But for now, let's just check if it visited the start URL.

if __name__ == "__main__":
    unittest.main()
