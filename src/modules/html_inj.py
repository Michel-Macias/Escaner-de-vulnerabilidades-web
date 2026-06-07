import logging

from src.modules.base import BaseVulnerability

logger = logging.getLogger(__name__)


class HTMLInjection(BaseVulnerability):
    """
    Módulo de escaneo para detectar vulnerabilidades de Inyección HTML (HTMLi).
    Verifica si etiquetas o estructuras HTML inyectadas se renderizan sin escapar en la respuesta.
    """
    def scan(self, form):
        """
        Prueba payloads de inyección HTML en todos los campos del formulario.
        
        Args:
            form: Diccionario con los datos estructurales del formulario.
            
        Returns:
            list: Hallazgos de inyección HTML detectados.
        """
        results = []
        # Payloads de prueba que contienen etiquetas HTML y estilos en línea
        payloads = ["<h1>HTML_INJECTION_TEST</h1>", "<div style='position:absolute;top:0;left:0'>INJECTED</div>"]

        target_url = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        logger.info("[*] Scanning HTML Injection at %s", target_url)

        # Iterar por los campos de texto o áreas de texto del formulario
        for input_field in inputs:
            if input_field["type"] in ["submit", "button", "reset"]:
                continue

            for payload in payloads:
                # Reconstruir datos inyectando el payload en el campo actual
                data = {inp["name"]: inp["value"] or "test" for inp in inputs if inp["name"]}
                data[input_field["name"]] = payload

                if method == "post":
                    res = self.requester.post(target_url, data=data)
                else:
                    res = self.requester.get(target_url, params=data)

                # Si el payload completo e intacto se encuentra en la respuesta, hay vulnerabilidad
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
                    break  # Detener fuzzing para este campo tras el primer hallazgo

        return results
