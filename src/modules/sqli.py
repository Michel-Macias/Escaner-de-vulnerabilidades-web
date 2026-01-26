from src.modules.base import BaseVulnerability

class SQLInjection(BaseVulnerability):
    def scan(self, form):
        results = []
        payloads = ["'", "\"", " OR 1=1", "' OR '1'='1"]
        errors = ["syntax error", "mysql_fetch", "ORA-", "PostgreSQL"]

        target_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        print(f"[*] Scanning for SQLi in {target_url}")

        for input_field in inputs:
            if input_field["type"] in ["submit", "button"]:
                continue
            
            # Baseline request for Boolean-based comparison
            baseline_data = {inp["name"]: inp["value"] or "test" for inp in inputs if inp["name"]}
            if method == "post":
                base_res = self.requester.post(target_url, data=baseline_data)
            else:
                base_res = self.requester.get(target_url, params=baseline_data)
            
            base_len = len(base_res.text) if base_res else 0

            for payload in payloads:
                data = {inp["name"]: inp["value"] or "test" for inp in inputs if inp["name"]}
                data[input_field["name"]] = payload

                if method == "post":
                    res = self.requester.post(target_url, data=data)
                else:
                    res = self.requester.get(target_url, params=data)

                if not res:
                    continue

                # 1. Error-based detection
                for error in errors:
                    if error.lower() in res.text.lower():
                        results.append({
                            "type": "SQL Injection (Error-based)",
                            "url": target_url,
                            "payload": payload,
                            "field": input_field["name"],
                            "evidence": error
                        })
                        print(f"[!] SQLi (Error) Found! {target_url} parameter: {input_field['name']}")
                        break
                
                # 2. Basic Boolean-based detection (if not already found by error)
                # This is a very simplified version
                if "OR 1=1" in payload and len(res.text) != base_len and base_len > 0:
                    # Double check with a false condition
                    false_payload = payload.replace("1=1", "1=2")
                    data[input_field["name"]] = false_payload
                    if method == "post":
                        res_false = self.requester.post(target_url, data=data)
                    else:
                        res_false = self.requester.get(target_url, params=data)
                    
                    if res_false and len(res_false.text) != len(res.text):
                        results.append({
                            "type": "SQL Injection (Boolean-based)",
                            "url": target_url,
                            "payload": payload,
                            "field": input_field["name"],
                            "evidence": "Response length varies with logical condition"
                        })
                        print(f"[!] SQLi (Boolean) Found! {target_url} parameter: {input_field['name']}")

        return results
