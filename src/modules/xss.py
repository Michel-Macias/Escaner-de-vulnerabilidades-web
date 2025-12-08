from src.modules.base import BaseVulnerability

class XSS(BaseVulnerability):
    def scan(self, form):
        results = []
        payload = "<script>alert('XSS')</script>"
        
        target_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        print(f"[*] Scanning for XSS in {target_url}")

        for input_field in inputs:
            if input_field["type"] in ["submit", "button"]:
                continue
            
            data = {input_field["name"]: payload}
            # Fill other fields
            for other_input in inputs:
                if other_input["name"] != input_field["name"]:
                    data[other_input["name"]] = "test"

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
        
        return results
