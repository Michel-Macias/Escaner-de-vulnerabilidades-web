import logging
import random
import time

import requests

logger = logging.getLogger(__name__)


class RequestManager:
    def __init__(self, proxies=None, delay=0, allow_redirects=True, timeout=15):
        self.session = requests.Session()
        self.proxies = proxies or []
        self.delay = delay
        self.allow_redirects = bool(allow_redirects)
        self.timeout = timeout
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        ]
        self.session.headers.update({
            "User-Agent": self._get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        })
        self.session.verify = True

    def update_session(self, session):
        """Updates the current session with a new one (e.g. after login)"""
        self.session = session

    def _get_random_user_agent(self):
        return random.choice(self.user_agents)

    def _apply_stealth(self):
        if self.delay > 0:
            time.sleep(random.uniform(0.5, self.delay))
        if self.proxies:
            proxy = random.choice(self.proxies)
            self.session.proxies.update({"http": proxy, "https": proxy})
        self.session.headers.update({"User-Agent": self._get_random_user_agent()})

    def get(self, url, **kwargs):
        try:
            self._apply_stealth()
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.allow_redirects,
                **kwargs,
            )
            return response
        except requests.exceptions.SSLError as e:
            logger.warning("SSL error en GET %s: %s", url, e)
            return None
        except requests.exceptions.ConnectionError as e:
            logger.warning("Connection error en GET %s: %s", url, e)
            return None
        except requests.exceptions.Timeout:
            logger.warning("Timeout en GET %s", url)
            return None
        except requests.RequestException as e:
            logger.warning("Error GET %s: %s", url, e)
            return None

    def post(self, url, data=None, **kwargs):
        try:
            self._apply_stealth()
            response = self.session.post(
                url,
                data=data,
                timeout=self.timeout,
                allow_redirects=self.allow_redirects,
                **kwargs,
            )
            return response
        except requests.exceptions.SSLError as e:
            logger.warning("SSL error en POST %s: %s", url, e)
            return None
        except requests.exceptions.ConnectionError as e:
            logger.warning("Connection error en POST %s: %s", url, e)
            return None
        except requests.exceptions.Timeout:
            logger.warning("Timeout en POST %s", url)
            return None
        except requests.RequestException as e:
            logger.warning("Error POST %s: %s", url, e)
            return None
