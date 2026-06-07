import logging

from src.modules.base import BaseVulnerability

logger = logging.getLogger(__name__)


class SQLInjection(BaseVulnerability):
    def __init__(self, requester, *, sanitize_fn=None):
        super().__init__(requester)
        self.sanitize = sanitize_fn or (lambda s: s)

    def _build_data(self, inputs, override=None):
        if override is None:
            override = {}
        return {
            inp["name"]: override.get(inp["name"], inp["value"] or "test")
            for inp in inputs
            if inp["name"]
        }

    def scan(self, form):
        results = []
        payloads = ["'", "\"", " OR 1=1", "' OR '1'='1"]
        errors = ["syntax error", "mysql_fetch", "ORA-", "PostgreSQL", "you have an error in your sql syntax", "warning: sql server"]

        target_url = self.sanitize(form["action"])
        method = form["method"]
        inputs = form["inputs"]

        logger.info("[*] Scanning SQLi at %s", target_url)

        for input_field in inputs:
            if input_field["type"] in ["submit", "button", "reset"]:
                continue

            baseline_data = self._build_data(inputs)
            base_res = self.requester.post(target_url, data=baseline_data) if method == "post" else self.requester.get(target_url, params=baseline_data)
            base_text = base_res.text if base_res else ""
            base_len = len(base_text)

            for payload in payloads:
                data = dict(baseline_data)
                data[input_field["name"]] = payload

                res = self.requester.post(target_url, data=data) if method == "post" else self.requester.get(target_url, params=data)
                if not res:
                    continue

                text = res.text

                for err in errors:
                    if err.lower() in text.lower():
                        results.append({
                            "type": "SQL Injection (Error-based)",
                            "url": target_url,
                            "payload": payload,
                            "field": input_field["name"],
                            "severity": "High",
                            "evidence": err,
                            "remediation": "Usa consultas parametrizadas/prepared statements nunca concatenes entrada de usuario en SQL.",
                        })
                        logger.warning("[!] SQLi (Error) en %s -> %s", target_url, input_field["name"])
                        break

                if "OR 1=1" in payload and base_len > 0 and payload not in text:
                    false_data = dict(data)
                    false_data[input_field["name"]] = payload.replace("1=1", "1=2")
                    res_false = (
                        self.requester.post(target_url, data=false_data) if method == "post"
                        else self.requester.get(target_url, params=false_data)
                    )
                    if res_false and len(res_false.text) != len(text):
                        results.append({
                            "type": "SQL Injection (Boolean-based)",
                            "url": target_url,
                            "payload": payload,
                            "field": input_field["name"],
                            "severity": "High",
                            "evidence": f"Baseline {base_len} chars vs payload {len(text)} chars.",
                            "remediation": "Emplea parametrización y validación estricta de tipos en todas las consultas.",
                        })
                        logger.warning("[!] SQLi (Boolean) en %s -> %s", target_url, input_field["name"])

        return results
