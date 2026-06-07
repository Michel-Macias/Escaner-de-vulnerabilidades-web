import logging

from src.modules.base import BaseVulnerability

logger = logging.getLogger(__name__)


class LDAPInjection(BaseVulnerability):
    def __init__(self, requester, *, sanitize_fn=None):
        super().__init__(requester)
        self.sanitize = sanitize_fn or (lambda s: s)

    def scan(self, form):
        results = []
        payloads = ["*", ")(cn=*))", "admin*)"]
        errors = ["IPWorks ASP.NET LDAP", "Module LDAP", "LDAPException", "naming exception"]

        target_url = self.sanitize(form["action"])
        method = form["method"]
        inputs = form["inputs"]

        logger.info("[*] Scanning LDAP Injection at %s", target_url)

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

                if res:
                    text = res.text.lower()
                    for err in errors:
                        if err.lower() in text:
                            results.append({
                                "type": "LDAP Injection",
                                "url": target_url,
                                "payload": payload,
                                "field": input_field["name"],
                                "severity": "Medium",
                                "evidence": err,
                                "remediation": "Escapa caracteres especiales LDAP; usa binding directo en lugar de construir queries por concatenación.",
                            })
                            logger.warning("[!] LDAP Injection Found! %s -> %s", target_url, input_field["name"])
                            break

        return results
