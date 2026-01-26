from src.modules.base import BaseVulnerability

class XSS(BaseVulnerability):
    def scan(self, form):
        results = []
        target_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        print(f"[*] Scanning for XSS in {target_url}")

        for input_field in inputs:
            if input_field["type"] in ["submit", "button"]:
                continue
            
            for payload in payloads:
                data = {inp["name"]: inp["value"] or "test" for inp in inputs if inp["name"]}
                data[input_field["name"]] = payload

                if method == "post":
                    res = self.requester.post(target_url, data=data)
                else:
                    res = self.requester.get(target_url, params=data)

                if res and payload in res.text:
                    results.append({
                        "type": "Reflected XSS",
                        "url": target_url,
                        "payload": payload,
                        "field": input_field["name"]
                    })
                    print(f"[!] XSS Found! {target_url} parameter: {input_field['name']}")
                    break # Found one for this field, move to next field
        
        return results
