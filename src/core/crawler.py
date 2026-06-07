import aiohttp
import asyncio
import logging
from urllib.parse import urlparse, urljoin

from src.core.extractor import FormExtractor
from src.core.requester import RequestManager

logger = logging.getLogger(__name__)


class Crawler:
    def __init__(self, target_url, concurrency=10, cookies=None, max_urls=200, max_depth=2):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.visited_urls = set()
        self.forms = []
        self.requester = RequestManager()  # Keep for sync modules
        self.extractor = FormExtractor()
        self.concurrency = concurrency
        self.session = None
        self.cookies = cookies
        self.max_urls = max(max_urls, 1)
        self.max_depth = max(max_depth, 0)
        self._url_count = 0

    def is_valid_url(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.netloc == self.domain

    def _depth_for(self, url):
        return url.count("/") - self.target_url.count("/")

    async def run(self):
        logger.info("[*] Starting async crawl on %s", self.target_url)
        self.visited_urls.add(self.target_url)
        self._url_count = 1

        try:
            async with aiohttp.ClientSession(cookies=self.cookies) as session:
                self.session = session
                queue = asyncio.Queue()
                queue.put_nowait(self.target_url)

                workers = [
                    asyncio.create_task(self.worker(queue)) for _ in range(self.concurrency)
                ]
                await queue.join()

                for w in workers:
                    w.cancel()
        except Exception as e:
            logger.error("Crawl session error: %s", e)

        logger.info(
            "[*] Crawl finished. Found %s URLs and %s forms.",
            len(self.visited_urls),
            len(self.forms),
        )
        return self.visited_urls, self.forms

    async def worker(self, queue):
        while True:
            url = await queue.get()
            try:
                await self.process_url(url, queue)
            except Exception as e:
                logger.error("Error processing %s: %s", url, e)
            finally:
                queue.task_done()

    async def process_url(self, url, queue):
        logger.debug("[*] Crawling: %s", url)
        if self._url_count >= self.max_urls:
            return
        if self._depth_for(url) > self.max_depth:
            return

        try:
            async with self.session.get(url, timeout=10) as response:
                if response.status != 200:
                    return
                html = await response.text()

                new_forms = self.extractor.extract_forms(html, url)
                if new_forms:
                    self.forms.extend(new_forms)

                links = self.extractor.extract_links(html, url)
                for link in links:
                    if (
                        link not in self.visited_urls
                        and self.is_valid_url(link)
                        and self._depth_for(link) <= self.max_depth
                    ):
                        self.visited_urls.add(link)
                        self._url_count += 1
                        if self._url_count < self.max_urls:
                            queue.put_nowait(link)
        except Exception:
            # Silent fail on network errors; keep crawl resilient.
            pass
