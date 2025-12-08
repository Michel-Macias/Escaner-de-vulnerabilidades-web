from bs4 import BeautifulSoup
from urllib.parse import urljoin

class FormExtractor:
    def extract_forms(self, html_content, base_url):
        soup = BeautifulSoup(html_content, "html.parser")
        forms = []
        
        for form in soup.find_all("form"):
            form_details = {}
            action = form.attrs.get("action")
            method = form.attrs.get("method", "get").lower()
            
            # Handle relative URLs
            form_details["action"] = urljoin(base_url, action) if action else base_url
            form_details["method"] = method
            form_details["inputs"] = []
            
            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                input_value = input_tag.attrs.get("value", "")
                
                if input_name:
                    form_details["inputs"].append({
                        "type": input_type,
                        "name": input_name,
                        "value": input_value,
                        "tag": input_tag.name
                    })
            
            forms.append(form_details)
        
        return forms

    def extract_links(self, html_content, base_url):
        soup = BeautifulSoup(html_content, "html.parser")
        links = set()
        
        for a_tag in soup.find_all("a", href=True):
            href = a_tag.attrs.get("href")
            if href:
                full_url = urljoin(base_url, href)
                # Basic filtering to avoid mailto, tel, javascript
                if full_url.startswith("http"):
                    links.add(full_url)
                    
        return list(links)
