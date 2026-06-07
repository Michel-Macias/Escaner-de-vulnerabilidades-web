class BaseVulnerability:
    """
    Clase base para todos los módulos de detección de vulnerabilidades.
    Proporciona la interfaz común y almacena el gestor de peticiones (requester).
    """
    def __init__(self, requester):
        """
        Inicializa el módulo con el gestor de peticiones.
        
        Args:
            requester: Instancia de RequestManager usada para enviar peticiones HTTP.
        """
        self.requester = requester
        self.vulnerabilities = []

    def scan(self, target):
        """
        Realiza el escaneo de vulnerabilidades en el objetivo.
        Debe ser implementado por las subclases.

        Args:
            target: Diccionario con los datos del formulario o URL a escanear.
            
        Returns:
            list: Lista de diccionarios con los hallazgos encontrados.
        """
        raise NotImplementedError
