from urllib.parse import urlparse, urljoin
from src.core.requester import RequestManager
from src.core.extractor import FormExtractor

class Crawler:
    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.visited_urls = set()
        self.forms = []
        self.requester = RequestManager()
        self.extractor = FormExtractor()

    def is_valid_url(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.netloc == self.domain

    def run(self):
        print(f"[*] Starting crawl on {self.target_url}")
        self.crawl(self.target_url)
        print(f"[*] Crawl finished. Found {len(self.visited_urls)} URLs and {len(self.forms)} forms.")
        return self.visited_urls, self.forms

    def crawl(self, url):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        print(f"[*] Crawling: {url}")

        response = self.requester.get(url)
        if not response or response.status_code != 200:
            return

        # Extract Forms
        new_forms = self.extractor.extract_forms(response.text, url)
        self.forms.extend(new_forms)

        # Extract Links
        links = self.extractor.extract_links(response.text, url)
        for link in links:
            if self.is_valid_url(link):
                self.crawl(link)
