from src.modules.base import BaseVulnerability
import time

class CommandInjection(BaseVulnerability):
    def scan(self, form):
        results = []
        # Echo based
        echo_payload = "; echo CMD_INJ_TEST"
        echo_check = "CMD_INJ_TEST"
        
        target_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        echo_payloads = ["; echo CMD_INJ_TEST", "| echo CMD_INJ_TEST", "`echo CMD_INJ_TEST`", "$(echo CMD_INJ_TEST)"]
        sleep_payloads = ["; sleep 5", "| sleep 5", "`sleep 5`", "& sleep 5"]
        echo_check = "CMD_INJ_TEST"

        print(f"[*] Scanning for Command Injection in {target_url}")

        for input_field in inputs:
            if input_field["type"] in ["submit", "button"]:
                continue
            
            # 1. Echo Based Tests
            for payload in echo_payloads:
                data = {inp["name"]: inp["value"] or "test" for inp in inputs if inp["name"]}
                data[input_field["name"]] = payload

                if method == "post":
                    res = self.requester.post(target_url, data=data)
                else:
                    res = self.requester.get(target_url, params=data)

                if res and echo_check in res.text:
                    results.append({
                        "type": "Command Injection (Echo-based)",
                        "url": target_url,
                        "payload": payload,
                        "field": input_field["name"]
                    })
                    print(f"[!] Command Injection (Echo) Found! {target_url} parameter: {input_field['name']}")
                    break # Move to next field if successful

            # 2. Time Based Tests (If echo failed)
            if not any(r["field"] == input_field["name"] for r in results):
                for payload in sleep_payloads:
                    data = {inp["name"]: inp["value"] or "test" for inp in inputs if inp["name"]}
                    data[input_field["name"]] = payload
                    
                    start_time = time.time()
                    if method == "post":
                        self.requester.post(target_url, data=data)
                    else:
                        self.requester.get(target_url, params=data)
                    
                    duration = time.time() - start_time
                    if duration >= 5:
                        results.append({
                            "type": "Command Injection (Time-based)",
                            "url": target_url,
                            "payload": payload,
                            "field": input_field["name"]
                        })
                        print(f"[!] Command Injection (Time) Found! {target_url} parameter: {input_field['name']}")
                        break

        return results
