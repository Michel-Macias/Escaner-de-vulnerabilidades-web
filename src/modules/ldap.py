from src.modules.base import BaseVulnerability

class LDAPInjection(BaseVulnerability):
    def scan(self, form):
        results = []
        payloads = ["*", ")(cn=*))", "admin*)"]
        errors = ["IPWorks ASP.NET LDAP", "Module LDAP", "LDAPException"]

        target_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        print(f"[*] Scanning for LDAP Injection in {target_url}")

        for input_field in inputs:
            if input_field["type"] in ["submit", "button"]:
                continue
            
            for payload in payloads:
                data = {input_field["name"]: payload}
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
                                "type": "LDAP Injection",
                                "url": target_url,
                                "payload": payload,
                                "field": input_field["name"],
                                "evidence": error
                            })
                            print(f"[!] LDAP Injection Found! {target_url} parameter: {input_field['name']}")
                            break
        return results
