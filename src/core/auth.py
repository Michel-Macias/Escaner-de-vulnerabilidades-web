import requests
from src.core.requester import RequestManager

class LoginManager:
    def __init__(self, requester):
        self.requester = requester

    def login(self, login_url, username, password, username_field="username", password_field="password"):
        """
        Attempts to log in to the target website.
        Returns True if successful (session cookies set), False otherwise.
        """
        print(f"[*] Attempting login at {login_url} with user: {username}")
        
        data = {
            username_field: username,
            password_field: password,
            "Login": "Login" # Common submit button name, might need to be dynamic
        }
        
        # Some forms need a CSRF token first, but for now we try direct POST
        # A more advanced version would GET the page first to extract tokens.
        
        try:
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
