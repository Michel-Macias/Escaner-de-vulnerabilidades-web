import logging

from src.modules.base import BaseVulnerability


class HTMLInjection(BaseVulnerability):
    def scan(self, form):
        results = []
        payloads = ["<h1>HTML_INJECTION_TEST</h1>", "<div style='position:absolute;top:0;left:0'>INJECTED</div>"]

        target_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        logger.info("[*] Scanning HTML Injection at %s", target_url)

        for input_field in inputs:
            if input_field["type"] in ["submit", "button", "reset"]:
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
                        "type": "HTML Injection",
                        "url": target_url,
                        "payload": payload,
                        "field": input_field["name"],
                        "severity": "Low",
                        "evidence": f"Reflected payload intact in response body ({len(res.text)} chars).",
                        "remediation": "Escapa salida del lado servidor con encoding contextual (HTML attribute/JS/URL).",
                    })
                    logger.warning("[!] HTML Injection Found! %s -> %s", target_url, input_field["name"])
                    break

        return results
