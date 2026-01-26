# 🛡️ Web Vulnerability Scanner (P10)

> **Herramienta Educativa de Ciberseguridad para Análisis de Vulnerabilidades Web**

![Python](https://img.shields.io/badge/Python-3.12-blue?style=for-the-badge&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red?style=for-the-badge&logo=streamlit)
![Playwright](https://img.shields.io/badge/Playwright-Headless-green?style=for-the-badge&logo=playwright)
![AsyncIO](https://img.shields.io/badge/AsyncIO-High%20Performance-orange?style=for-the-badge)

> **🔴 LIVE DEMO:** [scanner-vuln-web-maciasit.streamlit.app](https://scanner-vuln-web-maciasit.streamlit.app/)

## 📖 Introducción

Este proyecto es un **Escáner de Vulnerabilidades Web** de nivel profesional, desarrollado con fines educativos y de auditoría ética. A diferencia de las herramientas automatizadas simples, este escáner ha sido construido modularmente para simular el comportamiento de un *pentester* real, combinando técnicas de rastreo (crawling), detección de tecnologías (fingerprinting) y explotación controlada.

El objetivo no es solo encontrar fallos, sino **entender cómo funcionan**. Por ello, esta documentación incluye una sección educativa sobre las vulnerabilidades que detecta.

---

## 🚀 Características Avanzadas

### 🧠 Motor Inteligente
- **Crawler Asíncrono**: Utiliza `aiohttp` y `asyncio` para mapear sitios web a velocidad extrema, procesando múltiples peticiones en paralelo.
- **Motor Headless (Playwright)**: Integra un navegador Chromium real para renderizar JavaScript y detectar vulnerabilidades en aplicaciones modernas (SPA) como React, Angular o Vue.
- **Fingerprinting**: Identifica el servidor web (Apache, Nginx), el lenguaje (PHP, Python) y el CMS (WordPress, Joomla) antes de atacar, buscando CVEs conocidos.

### 🕵️ Modo Sigilo (Stealth)
- **Evasión de WAF**: Capacidad para rotar User-Agents, usar servidores Proxy (Tor/SOCKS5) e introducir retardos aleatorios (Jitter) para evitar bloqueos por IP.

### 📊 Dashboard & Reportes
- **Interfaz Gráfica**: Control total desde un dashboard web creado con Streamlit.
- **Reportes PDF**: Generación automática de informes ejecutivos con clasificación de riesgo (Alto, Medio, Bajo).
- **Guía de Usuario Integrada**: Documentación completa accesible directamente desde la aplicación para facilitar su uso.

---

## 🎓 Rincón Educativo: ¿Qué estamos buscando?

Este escáner detecta las siguientes vulnerabilidades críticas (OWASP Top 10):

### 1. SQL Injection (SQLi) 💉
*   **¿Qué es?**: Ocurre cuando una aplicación inserta datos del usuario directamente en una consulta de base de datos sin validación.
*   **Riesgo**: Un atacante puede leer toda la base de datos, modificar datos o incluso tomar control del servidor.
*   **Cómo lo detectamos**: Inyectamos comillas `'` y payloads lógicos (`OR 1=1`) para ver si la web devuelve errores de SQL o cambia su comportamiento (Boolean-based).

### 2. Cross-Site Scripting (XSS) 🎭
*   **¿Qué es?**: Permite inyectar scripts maliciosos (JavaScript) que se ejecutan en el navegador de otros usuarios.
*   **Riesgo**: Robo de cookies de sesión, redirecciones a sitios de phishing o defacement.
*   **Cómo lo detectamos**:
    *   **Reflected**: Inyectamos `<script>alert(1)</script>` en inputs y vemos si aparece en el HTML de respuesta.
    *   **DOM-based**: Usamos el motor Headless para ver si el JavaScript de la página ejecuta nuestro payload en el navegador.

### 3. Command Injection (RCE) 💻
*   **¿Qué es?**: El "Santo Grial" de los hackers. Ocurre cuando la web pasa datos a una consola de comandos del sistema operativo (ej. `ping`, `ls`).
*   **Riesgo**: Control total del servidor.
*   **Cómo lo detectamos**: Inyectamos comandos como `; sleep 5` o `| cat /etc/passwd` y medimos si la respuesta tarda más de lo normal (Time-based).

### 4. HTML Injection & LDAP Injection 📋
*   **HTML**: Inyección de etiquetas HTML para cambiar la apariencia de la web (Phishing).
*   **LDAP**: Manipulación de consultas a directorios LDAP para acceder a información de usuarios corporativos.

---

## 🛠️ Instalación

### Prerrequisitos
*   Python 3.8+
*   Google Chrome o Chromium (para el motor Headless)

### Pasos
1.  **Clonar el repositorio**:
    ```bash
    git clone https://github.com/Michel-Macias/Escaner-de-vulnerabilidades-web.git
    cd Escaner-de-vulnerabilidades-web
    ```

2.  **Crear entorno virtual** (Recomendado):
    ```bash
    python -m venv venv
    source venv/bin/activate  # En Linux/Mac
    # venv\Scripts\activate   # En Windows
    ```

3.  **Instalar dependencias**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Instalar navegadores para Playwright**:
    ```bash
    playwright install chromium
    ```

---

## 🎮 Guía de Uso

### Iniciar el Dashboard
Ejecuta el siguiente comando en tu terminal:
```bash
streamlit run app.py
```
Se abrirá automáticamente una pestaña en tu navegador (`http://localhost:8501`).

> **Tip**: Usa el menú de navegación en la barra lateral para alternar entre el **Escáner** y la **Guía de Usuario**.

### Configuración del Escaneo
1.  **Target URL**: Introduce la URL completa (ej. `http://testphp.vulnweb.com` o `http://localhost:3000`).
2.  **Authentication (Opcional)**:
    *   Si la web requiere login, activa esta casilla.
    *   Introduce la URL del formulario de login y tus credenciales. El escáner obtendrá la cookie de sesión automáticamente.
3.  **Stealth Mode (Opcional)**:
    *   Actívalo si el servidor te bloquea.
    *   Aumenta el "Request Delay" para ir más lento y pasar desapercibido.
4.  **Scan Modules**:
    *   Selecciona qué vulnerabilidades buscar.
    *   ⚠️ **Headless DOM XSS**: Actívalo para webs modernas (SPA). Es más lento pero mucho más efectivo.

### Resultados
*   Verás el progreso en tiempo real.
*   Al finalizar, podrás descargar un **Reporte PDF** con todos los hallazgos detallados.

---

## ⚠️ Aviso Legal (Disclaimer)

Esta herramienta ha sido creada **exclusivamente para fines educativos y pruebas de seguridad autorizadas**.
*   **NO** la utilices contra servidores de los que no tengas permiso explícito por escrito.
*   El autor no se hace responsable del mal uso de este software.

## 🛡️ Mejoras Recientes (Enero 2026)

Se ha realizado una auditoría y actualización completa del motor:
- **Actualización de Seguridad**: Dependencias actualizadas a sus versiones más recientes (`requests`, `playwright`, `aiohttp`, etc.).
- **Detección Avanzada de SQLi**: Implementación de lógica **Boolean-based** para detectar vulnerabilidades que no devuelven errores visibles.
- **Mejora en XSS**: Ampliación del diccionario de payloads y mejora en el motor de detección por reflexión.
- **Soporte de Autenticación Robusto**: El escáner ahora detecta automáticamente tokens **CSRF** en los formularios de login y mantiene la sesión asíncrona correctamente.
- **Fingerprinting Expandido**: Añadido soporte para detectar frameworks modernos como Laravel, Django, Flask y Express.
- **Calidad de Código**: Introducción de tests automáticos con `pytest` y `pytest-asyncio`.

---
© 2026 Web Vuln Scanner Project
