
def get_user_guide_markdown():
    return """
# 📘 Guía de Usuario - Web Vulnerability Scanner

Bienvenido a la guía oficial del **Web Vulnerability Scanner**. Esta herramienta ha sido diseñada para auditar la seguridad de aplicaciones web de forma ética y profesional.

---

## 🚀 Inicio Rápido

### 1. Configuración Básica
En la barra lateral izquierda encontrarás el panel de configuración:

*   **Target URL**: Es la dirección web que quieres escanear. Asegúrate de incluir el protocolo (`http://` o `https://`).
    *   *Ejemplo*: `http://localhost:8081` o `http://testphp.vulnweb.com`

### 2. Módulos de Escaneo
Selecciona qué tipos de vulnerabilidades quieres buscar. Por defecto, los más críticos están activados:

*   **SQL Injection (SQLi)**: Intenta manipular la base de datos.
*   **XSS (Cross-Site Scripting)**: Busca inyecciones de scripts en el navegador.
*   **HTML Injection**: Verifica si es posible inyectar código HTML arbitrario.
*   **Command Injection**: Comprueba si se pueden ejecutar comandos del sistema operativo.
*   **LDAP Injection**: (Opcional) Busca fallos en directorios LDAP.
*   **Headless DOM XSS**: (Opcional) Usa un navegador real para detectar XSS complejos. *Nota: Es más lento.*

### 3. Iniciar Escaneo
Pulsa el botón **"Start Scan"**. El escáner comenzará a:
1.  **Crawling**: Mapear todas las páginas y formularios del sitio.
2.  **Fingerprinting**: Detectar tecnologías (CMS, Servidor, Lenguaje).
3.  **Attacking**: Probar payloads seguros contra los formularios detectados.

---

## 🔐 Autenticación (Login)

Si la aplicación requiere usuario y contraseña, puedes configurar el escáner para que inicie sesión automáticamente.

1.  Activa la casilla **"Enable Login"**.
2.  **Login URL**: La dirección exacta donde está el formulario de login (ej. `/login.php`).
3.  **Username / Password**: Tus credenciales de prueba.

> **¿Cómo funciona?**
> El escáner enviará una petición POST con tus credenciales, capturará las **Cookies de Sesión** y las usará en todas las peticiones siguientes para escanear zonas privadas.

---

## 🕵️ Modo Sigilo (Stealth Mode)

Útil si el servidor tiene medidas de seguridad (WAF) o te bloquea por muchas peticiones.

1.  Activa **"Enable Stealth"**.
2.  **Request Delay**: Añade una pausa entre peticiones (ej. 1-2 segundos) para parecer un humano.
3.  **Proxies**: Puedes añadir una lista de proxies para rotar tu IP.

---

## 📊 Interpretación de Resultados

Al finalizar, verás una tabla con los hallazgos:

*   **Type**: El tipo de vulnerabilidad (ej. SQL Injection).
*   **URL**: Dónde se encontró.
*   **Payload**: El código que provocó el fallo.
*   **Severity**:
    *   🔴 **High**: Crítico (SQLi, RCE). Requiere atención inmediata.
    *   🟠 **Medium**: Riesgo medio (XSS Reflected).
    *   🟡 **Low**: Informativo o bajo riesgo.

### 📄 Reporte PDF
Puedes descargar un informe detallado pulsando el botón **"Download PDF Report"**. Este informe es ideal para presentar a clientes o equipos de desarrollo.

---

## ⚠️ Solución de Problemas

*   **El escáner no encuentra nada**:
    *   Asegúrate de que la URL es correcta.
    *   Si la web usa mucho JavaScript (React/Angular), activa **Headless DOM XSS**.
*   **Error de Login**:
    *   Verifica las credenciales.
    *   Algunos logins complejos (CAPTCHA, 2FA) no son soportados automáticamente.

---
*© 2025 Web Vuln Scanner Project - Educational Use Only*
"""
