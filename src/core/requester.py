import requests
import random

class RequestManager:
    def __init__(self):
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36"
        ]
        self.session.headers.update({
            "User-Agent": self._get_random_user_agent()
        })

    def _get_random_user_agent(self):
        return random.choice(self.user_agents)

    def get(self, url, **kwargs):
        try:
            # Rotate UA on each request (optional, but good for stealth)
            self.session.headers.update({"User-Agent": self._get_random_user_agent()})
            response = self.session.get(url, timeout=10, **kwargs)
            return response
        except requests.RequestException as e:
            print(f"[-] Error making GET request to {url}: {e}")
            return None

    def post(self, url, data=None, **kwargs):
        try:
            self.session.headers.update({"User-Agent": self._get_random_user_agent()})
            response = self.session.post(url, data=data, timeout=10, **kwargs)
            return response
        except requests.RequestException as e:
            print(f"[-] Error making POST request to {url}: {e}")
            return None
