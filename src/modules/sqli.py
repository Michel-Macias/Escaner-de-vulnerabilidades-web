import logging

from src.modules.base import BaseVulnerability

logger = logging.getLogger(__name__)


class SQLInjection(BaseVulnerability):
    """
    Módulo de escaneo para detectar vulnerabilidades de Inyección SQL (SQLi).
    Soporta detección basada en errores y detección basada en booleanos.
    """
    def __init__(self, requester, *, sanitize_fn=None):
        """
        Inicializa el escáner de SQLi.
        
        Args:
            requester: Instancia de RequestManager.
            sanitize_fn: Función opcional para sanitizar URLs de destino.
        """
        super().__init__(requester)
        self.sanitize = sanitize_fn or (lambda s: s)

    def _build_data(self, inputs, override=None):
        """
        Construye el cuerpo o parámetros de la petición simulando el formulario.
        Permite sobrescribir el valor de campos específicos (por ejemplo, con payloads).
        
        Args:
            inputs: Lista de campos del formulario.
            override: Diccionario de valores a sobrescribir {nombre_campo: valor_payload}.
        """
        if override is None:
            override = {}
        return {
            inp["name"]: override.get(inp["name"], inp["value"] or "test")
            for inp in inputs
            if inp["name"]
        }

    def scan(self, form):
        """
        Ejecuta el escaneo de SQLi sobre un formulario específico.
        Prueba payloads comunes en cada campo de entrada y analiza las respuestas.
        
        Args:
            form: Diccionario con la estructura del formulario (action, method, inputs).
            
        Returns:
            list: Hallazgos de vulnerabilidades SQLi detectadas.
        """
        results = []
        # Payloads de prueba típicos para inyectar en campos
        payloads = ["'", "\"", " OR 1=1", "' OR '1'='1"]
        # Firmas de error de bases de datos conocidas
        errors = ["syntax error", "mysql_fetch", "ORA-", "PostgreSQL", "you have an error in your sql syntax", "warning: sql server"]

        target_url = self.sanitize(form["action"])
        method = form["method"]
        inputs = form["inputs"]

        logger.info("[*] Scanning SQLi at %s", target_url)

        # Iterar sobre cada campo de entrada del formulario
        for input_field in inputs:
            # Omitir botones y botones de envío
            if input_field["type"] in ["submit", "button", "reset"]:
                continue

            # Obtener respuesta base para comparar el comportamiento normal
            baseline_data = self._build_data(inputs)
            base_res = self.requester.post(target_url, data=baseline_data) if method == "post" else self.requester.get(target_url, params=baseline_data)
            base_text = base_res.text if base_res else ""
            base_len = len(base_text)

            # Probar cada uno de los payloads de SQLi
            for payload in payloads:
                data = dict(baseline_data)
                data[input_field["name"]] = payload

                # Enviar petición con el payload inyectado
                res = self.requester.post(target_url, data=data) if method == "post" else self.requester.get(target_url, params=data)
                if not res:
                    continue

                text = res.text

                # 1. Detección basada en Errores (Error-based SQLi)
                # Comprobar si la respuesta contiene algún mensaje de error típico de base de datos
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

                # 2. Detección basada en Booleanos (Boolean-based SQLi)
                # Si se inyecta un OR verdadero y la longitud cambia, validamos comparando con una condición falsa (OR 1=2)
                if "OR 1=1" in payload and base_len > 0 and payload not in text:
                    false_data = dict(data)
                    false_data[input_field["name"]] = payload.replace("1=1", "1=2")
                    res_false = (
                        self.requester.post(target_url, data=false_data) if method == "post"
                        else self.requester.get(target_url, params=false_data)
                    )
                    # Si el resultado con OR 1=1 difiere de OR 1=2, indica vulnerabilidad
                    if res_false and len(res_false.text) != len(text):
                        results.append({
                            "type": "SQL Injection (Boolean-based)",
                            "url": target_url,
                            "payload": payload,
                            "field": input_field["name"],
                            "severity": "High",
                            "evidence": "Baseline %s chars vs payload %s chars." % (base_len, len(text)),
                            "remediation": "Emplea parametrización y validación estricta de tipos en todas las consultas.",
                        })
                        logger.warning("[!] SQLi (Boolean) en %s -> %s", target_url, input_field["name"])

        return results
