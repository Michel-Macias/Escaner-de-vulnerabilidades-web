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
            
            for payload in payloads:
                data = {input_field["name"]: payload}
                # Fill other fields with dummy data
                for other_input in inputs:
                    if other_input["name"] != input_field["name"]:
                        data[other_input["name"]] = "test"

                if method == "post":
                    res = self.requester.post(target_url, data=data)
                else:
                    res = self.requester.get(target_url, params=data)

                if res:
                    for error in errors:
                        if error.lower() in res.text.lower():
                            results.append({
                                "type": "SQL Injection",
                                "url": target_url,
                                "payload": payload,
                                "field": input_field["name"],
                                "evidence": error
                            })
                            print(f"[!] SQLi Found! {target_url} parameter: {input_field['name']}")
                            break
        return results
