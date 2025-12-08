import aiohttp
import asyncio
from urllib.parse import urlparse, urljoin
from src.core.extractor import FormExtractor
from src.core.requester import RequestManager

class Crawler:
    def __init__(self, target_url, concurrency=10):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.visited_urls = set()
        self.forms = []
        self.requester = RequestManager() # Keep for sync modules
        self.extractor = FormExtractor()
        self.concurrency = concurrency
        self.session = None

    def is_valid_url(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.netloc == self.domain

    async def run(self):
        print(f"[*] Starting async crawl on {self.target_url}")
        self.visited_urls.add(self.target_url)
        
        async with aiohttp.ClientSession() as session:
            self.session = session
            queue = asyncio.Queue()
            queue.put_nowait(self.target_url)
            
            workers = [asyncio.create_task(self.worker(queue)) for _ in range(self.concurrency)]
            await queue.join()
            
            for w in workers:
                w.cancel()
                
        print(f"[*] Crawl finished. Found {len(self.visited_urls)} URLs and {len(self.forms)} forms.")
        return self.visited_urls, self.forms

    async def worker(self, queue):
        while True:
            url = await queue.get()
            try:
                await self.process_url(url, queue)
            except Exception as e:
                print(f"[-] Error processing {url}: {e}")
            finally:
                queue.task_done()

    async def process_url(self, url, queue):
        print(f"[*] Crawling: {url}")
        try:
            async with self.session.get(url, timeout=10) as response:
                if response.status != 200:
                    return
                html = await response.text()
                
                # Extract Forms
                new_forms = self.extractor.extract_forms(html, url)
                self.forms.extend(new_forms)

                # Extract Links
                links = self.extractor.extract_links(html, url)
                for link in links:
                    if link not in self.visited_urls and self.is_valid_url(link):
                        self.visited_urls.add(link)
                        queue.put_nowait(link)
        except Exception as e:
            # print(f"[-] Error fetching {url}: {e}")
            pass
