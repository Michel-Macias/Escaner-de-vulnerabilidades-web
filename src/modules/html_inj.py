from src.modules.base import BaseVulnerability

class HTMLInjection(BaseVulnerability):
    def scan(self, form):
        results = []
        payload = "<h1>HTML_INJECTION_TEST</h1>"
        
        target_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        print(f"[*] Scanning for HTML Injection in {target_url}")

        for input_field in inputs:
            if input_field["type"] in ["submit", "button"]:
                continue
            
            data = {input_field["name"]: payload}
            for other_input in inputs:
                if other_input["name"] != input_field["name"]:
                    data[other_input["name"]] = "test"

            if method == "post":
                res = self.requester.post(target_url, data=data)
            else:
                res = self.requester.get(target_url, params=data)

            if res and payload in res.text:
                results.append({
                    "type": "HTML Injection",
                    "url": target_url,
                    "payload": payload,
                    "field": input_field["name"]
                })
                print(f"[!] HTML Injection Found! {target_url} parameter: {input_field['name']}")
        
        return results
