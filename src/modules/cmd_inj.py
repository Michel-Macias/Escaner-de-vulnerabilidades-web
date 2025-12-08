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

        print(f"[*] Scanning for Command Injection in {target_url}")

        for input_field in inputs:
            if input_field["type"] in ["submit", "button"]:
                continue
            
            # 1. Echo Test
            data = {input_field["name"]: echo_payload}
            for other_input in inputs:
                if other_input["name"] != input_field["name"]:
                    data[other_input["name"]] = "test"

            if method == "post":
                res = self.requester.post(target_url, data=data)
            else:
                res = self.requester.get(target_url, params=data)

            if res and echo_check in res.text:
                results.append({
                    "type": "Command Injection (Echo)",
                    "url": target_url,
                    "payload": echo_payload,
                    "field": input_field["name"]
                })
                print(f"[!] Command Injection (Echo) Found! {target_url} parameter: {input_field['name']}")
                continue # Skip time based if echo found

            # 2. Time Based (Linux sleep)
            sleep_payload = "; sleep 5"
            start_time = time.time()
            
            data[input_field["name"]] = sleep_payload
            if method == "post":
                self.requester.post(target_url, data=data)
            else:
                self.requester.get(target_url, params=data)
            
            duration = time.time() - start_time
            if duration >= 5:
                results.append({
                    "type": "Command Injection (Time-Based)",
                    "url": target_url,
                    "payload": sleep_payload,
                    "field": input_field["name"]
                })
                print(f"[!] Command Injection (Time) Found! {target_url} parameter: {input_field['name']}")

        return results
