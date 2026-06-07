import logging

from src.modules.base import BaseVulnerability

logger = logging.getLogger(__name__)


class LDAPInjection(BaseVulnerability):
    """
    Módulo de escaneo para detectar vulnerabilidades de Inyección LDAP.
    Prueba si payloads inyectados provocan excepciones o errores descriptivos de LDAP en la respuesta.
    """
    def __init__(self, requester, *, sanitize_fn=None):
        """
        Inicializa el escáner de LDAP.
        
        Args:
            requester: Instancia de RequestManager.
            sanitize_fn: Función opcional para sanitizar la URL de destino.
        """
        super().__init__(requester)
        self.sanitize = sanitize_fn or (lambda s: s)

    def scan(self, form):
        """
        Ejecuta el escaneo de Inyección LDAP sobre los campos del formulario provisto.
        
        Args:
            form: Estructura de formulario a analizar.
            
        Returns:
            list: Hallazgos de inyección LDAP encontrados.
        """
        results = []
        # Payloads LDAP comunes para intentar romper la sintaxis del filtro LDAP
        payloads = ["*", ")(cn=*))", "admin*)"]
        # Firmas o mensajes de error típicos de servidores LDAP
        errors = ["IPWorks ASP.NET LDAP", "Module LDAP", "LDAPException", "naming exception"]

        target_url = self.sanitize(form["action"])
        method = form["method"]
        inputs = form["inputs"]

        logger.info("[*] Scanning LDAP Injection at %s", target_url)

        for input_field in inputs:
            if input_field["type"] in ["submit", "button", "reset"]:
                continue

            for payload in payloads:
                # Construir el cuerpo de la petición con el payload
                data = {inp["name"]: inp["value"] or "test" for inp in inputs if inp["name"]}
                data[input_field["name"]] = payload

                if method == "post":
                    res = self.requester.post(target_url, data=data)
                else:
                    res = self.requester.get(target_url, params=data)

                if res:
                    text = res.text.lower()
                    # Buscar firmas de error conocidas en la respuesta
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
                            break  # Detener escaneo del payload actual si se detectó vulnerabilidad

        return results
