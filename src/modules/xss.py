from src.modules.base import BaseVulnerability


class XSS(BaseVulnerability):
    def __init__(self, requester, *, sanitize_fn=None):
        super().__init__(requester)
        self.sanitize = sanitize_fn or (lambda s: s)

    def scan(self, form):
        results = []
        target_url = self.sanitize(form["action"])
        method = form["method"]
        inputs = form["inputs"]

        payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
        ]

        logger.info("[*] Scanning XSS at %s", target_url)

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

                if not res:
                    continue

                reflected = payload in res.text
                if reflected:
                    results.append({
                        "type": "Reflected XSS",
                        "url": target_url,
                        "payload": payload,
                        "field": input_field["name"],
                        "severity": "Medium",
                        "evidence": f"Payload reflected in response ({len(res.text)} chars).",
                        "remediation": "Escapa salida por contexto y aplica CSP y validación de entrada estricta.",
                    })
                    logger.warning("[!] XSS Found! %s -> %s", target_url, input_field["name"])
                    break

        return results
