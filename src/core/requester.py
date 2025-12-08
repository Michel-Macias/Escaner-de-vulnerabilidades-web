import requests
import random

import time

class RequestManager:
    def __init__(self, proxies=None, delay=0):
        self.session = requests.Session()
        self.proxies = proxies or []
        self.delay = delay
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36"
        ]
        self.session.headers.update({
            "User-Agent": self._get_random_user_agent()
        })

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
            response = self.session.get(url, timeout=10, **kwargs)
            return response
        except requests.RequestException as e:
            print(f"[-] Error making GET request to {url}: {e}")
            return None

    def post(self, url, data=None, **kwargs):
        try:
            self._apply_stealth()
            response = self.session.post(url, data=data, timeout=10, **kwargs)
            return response
        except requests.RequestException as e:
            print(f"[-] Error making POST request to {url}: {e}")
            return None
