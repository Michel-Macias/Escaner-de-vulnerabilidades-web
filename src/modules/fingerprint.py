import requests
from bs4 import BeautifulSoup

class Fingerprinter:
    def __init__(self, requester):
        self.requester = requester
        self.technologies = {
            "WordPress": {"meta": {"name": "generator", "content": "WordPress"}},
            "Joomla": {"meta": {"name": "generator", "content": "Joomla"}},
            "Drupal": {"meta": {"name": "generator", "content": "Drupal"}},
            "Apache": {"header": "Server", "content": "Apache"},
            "Nginx": {"header": "Server", "content": "nginx"},
            "PHP": {"header": "X-Powered-By", "content": "PHP"}
        }

    def scan(self, url):
        findings = []
        print(f"[*] Fingerprinting {url}")
        
        try:
            response = self.requester.get(url)
            if not response:
                return findings
            
            # Check Headers
            for tech, signature in self.technologies.items():
                if "header" in signature:
                    header_val = response.headers.get(signature["header"])
                    if header_val and signature["content"] in header_val:
                        findings.append({
                            "type": "Technology Detected",
                            "url": url,
                            "payload": f"{tech} ({header_val})",
                            "field": "Header",
                            "evidence": header_val
                        })
                        self._check_cves(tech, header_val, findings)

            # Check Meta Tags
            soup = BeautifulSoup(response.text, "html.parser")
            for tech, signature in self.technologies.items():
                if "meta" in signature:
                    meta = soup.find("meta", attrs=signature["meta"])
                    if meta:
                        content = meta.get("content", "")
                        if signature["content"] in content:
                            findings.append({
                                "type": "Technology Detected",
                                "url": url,
                                "payload": f"{tech} ({content})",
                                "field": "Meta Tag",
                                "evidence": content
                            })
                            self._check_cves(tech, content, findings)
                            
        except Exception as e:
            print(f"[-] Fingerprinting error: {e}")
            
        return findings

    def _check_cves(self, tech, version_string, findings):
        # Mock CVE lookup logic
        # In a real scenario, we would parse the version number and query NVD
        print(f"[*] Checking CVEs for {tech}...")
        
        # Example mock CVEs
        if tech == "WordPress" and "4.7" in version_string:
            findings.append({
                "type": "CVE Detected",
                "url": "N/A",
                "payload": "CVE-2017-5487",
                "field": "Version",
                "evidence": "WordPress 4.7 is vulnerable to Content Injection"
            })
        elif tech == "Apache" and "2.4.49" in version_string:
             findings.append({
                "type": "CVE Detected",
                "url": "N/A",
                "payload": "CVE-2021-41773",
                "field": "Version",
                "evidence": "Path Traversal in Apache 2.4.49"
            })
