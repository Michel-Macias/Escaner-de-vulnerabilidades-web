import logging

from src.modules.base import BaseVulnerability

logger = logging.getLogger(__name__)


class XSS(BaseVulnerability):
    """
    Módulo de escaneo para detectar vulnerabilidades de Cross-Site Scripting Reflejado (XSS).
    Prueba si los scripts inyectados se reflejan intactos en el cuerpo de la respuesta HTML.
    """
    def __init__(self, requester, *, sanitize_fn=None):
        """
        Inicializa el escáner XSS.
        
        Args:
            requester: Instancia de RequestManager.
            sanitize_fn: Función opcional para sanitizar la URL de destino.
        """
        super().__init__(requester)
        self.sanitize = sanitize_fn or (lambda s: s)

    def scan(self, form):
        """
        Ejecuta el escaneo de XSS reflejado inyectando diversos payloads en los campos del formulario.
        
        Args:
            form: Estructura del formulario a probar.
            
        Returns:
            list: Hallazgos de vulnerabilidades XSS encontradas.
        """
        results = []
        target_url = self.sanitize(form["action"])
        method = form["method"]
        inputs = form["inputs"]

        # Payloads HTML/JS comunes para probar la reflexión de scripts
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

        # Iterar por cada campo del formulario
        for input_field in inputs:
            if input_field["type"] in ["submit", "button", "reset"]:
                continue

            # Inyectar y enviar cada payload
            for payload in payloads:
                # Construir diccionario de datos con los valores base y el payload
                data = {inp["name"]: inp["value"] or "test" for inp in inputs if inp["name"]}
                data[input_field["name"]] = payload

                if method == "post":
                    res = self.requester.post(target_url, data=data)
                else:
                    res = self.requester.get(target_url, params=data)

                if not res:
                    continue

                # Verificar si el payload se refleja de forma idéntica en el código HTML
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
                    break  # Detener el fuzzing de este campo tras encontrar vulnerabilidad

        return results
