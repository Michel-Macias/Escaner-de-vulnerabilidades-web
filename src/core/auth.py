import requests
from src.core.requester import RequestManager

class LoginManager:
    def __init__(self, requester):
        self.requester = requester

    def login(self, login_url, username, password, username_field="username", password_field="password"):
        """
        Attempts to log in to the target website.
        """
        print(f"[*] Attempting login at {login_url} with user: {username}")
        
        # 1. GET the login page to capture cookies and look for CSRF tokens
        try:
            get_response = self.requester.get(login_url)
            if not get_response:
                return False
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(get_response.text, "html.parser")
            
            data = {
                username_field: username,
                password_field: password,
                "Login": "Login"
            }
            
            # Look for common CSRF token fields
            for input_tag in soup.find_all("input"):
                name = input_tag.get("name", "").lower()
                value = input_tag.get("value", "")
                if any(x in name for x in ["csrf", "token", "_token"]):
                    data[input_tag.get("name")] = value
                    print(f"[*] Detected potential CSRF token: {input_tag.get('name')}={value}")

            # 2. Perform the POST login
            response = self.requester.post(login_url, data=data)
            
            # Check if we got cookies
            if response and response.cookies:
                print("[+] Login successful! Session cookies captured.")
                return True
            else:
                print("[-] Login failed. No cookies received.")
                return False
                
        except Exception as e:
            print(f"[-] Login error: {e}")
            return False
