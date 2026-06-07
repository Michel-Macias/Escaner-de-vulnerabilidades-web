from src.modules.base import BaseVulnerability
import time

logger = logging.getLogger(__name__)


class CommandInjection(BaseVulnerability):
    def scan(self, form):
        results = []
        target_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        logger.info("[*] Scanning for Command Injection in %s", target_url)

        for input_field in inputs:
            if input_field["type"] in ["submit", "button", "reset"]:
                continue

            baseline_data = {inp["name"]: inp["value"] or "test" for inp in inputs if inp["name"]}
            base_res = self.requester.post(target_url, data=baseline_data) if method == "post" else self.requester.get(target_url, params=baseline_data)
            base_time = base_res.elapsed.total_seconds() if base_res and getattr(base_res, "elapsed", None) else 0.5
            threshold = max(float(base_time) * 2, 2.5)

            echo_payloads = [
                "; echo CMD_INJ_TEST",
                "| echo CMD_INJ_TEST",
                "`echo CMD_INJ_TEST`",
                "$(echo CMD_INJ_TEST)",
            ]
            checked_echo = False
            echo_matched = False

            for payload in echo_payloads:
                data = {inp["name"]: inp["value"] or "test" for inp in inputs if inp["name"]}
                data[input_field["name"]] = payload

                res = self.requester.post(target_url, data=data) if method == "post" else self.requester.get(target_url, params=data)
                if res and "CMD_INJ_TEST" in res.text:
                    results.append({
                        "type": "Command Injection (Echo-based)",
                        "url": target_url,
                        "payload": payload,
                        "field": input_field["name"],
                        "severity": "Critical",
                        "evidence": "Reflected CMD_INJ_TEST marker.",
                        "remediation": "Evita pasar entrada de usuario al shell; usa APIs nativas y listas blancas de comandos.",
                    })
                    logger.warning("[!] Command Injection (Echo) Found! %s -> %s", target_url, input_field["name"])
                    echo_matched = True
                    checked_echo = True
                    break

            if not echo_matched:
                checked_echo = True
                sleep_payloads = ["; sleep 5", "| sleep 5", "& sleep 5"]
                for payload in sleep_payloads:
                    data = {inp["name"]: inp["value"] or "test" for inp in inputs if inp["name"]}
                    data[input_field["name"]] = payload

                    start_time = time.time()
                    if method == "post":
                        self.requester.post(target_url, data=data)
                    else:
                        self.requester.get(target_url, params=data)

                    duration = time.time() - start_time
                    if duration >= threshold:
                        results.append({
                            "type": "Command Injection (Time-based)",
                            "url": target_url,
                            "payload": payload,
                            "field": input_field["name"],
                            "severity": "Critical",
                            "evidence": f"Request took {duration:.1f}s (threshold {threshold:.1f}s).",
                            "remediation": "Elimina exec/system/passthru sobre datos sin sanitizar estrictamente.",
                        })
                        logger.warning("[!] Command Injection (Time) Found! %s -> %s", target_url, input_field["name"])
                        break

        return results
