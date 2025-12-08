# Web Vulnerability Scanner (P10)

## Descripción
Este proyecto es un escáner de vulnerabilidades web de alto impacto diseñado para identificar fallos de seguridad críticos en aplicaciones web. Va más allá de las herramientas automatizadas básicas, implementando un motor de rastreo personalizado y módulos de detección específicos para simular el comportamiento de un pentester real.

## Características Principales
- **Crawler Inteligente**: Mapeo recursivo del sitio web y extracción de vectores de ataque.
- **Detección de Vulnerabilidades**:
    - SQL Injection (SQLi)
    - Cross-Site Scripting (XSS)
    - HTML Injection
    - Command Injection
    - LDAP Injection
- **Dashboard Interactivo**: Interfaz gráfica basada en Streamlit para visualización en tiempo real.
- **Reportes Profesionales**: Generación de informes en PDF con clasificación de severidad.

## Estructura del Proyecto
```text
web_scanner/
├── src/
│   ├── core/       # Motor de rastreo y extracción
│   ├── modules/    # Módulos de detección de vulnerabilidades
│   └── utils/      # Utilidades y generación de reportes
├── tests/          # Pruebas unitarias y de integración
├── docs/           # Documentación técnica
└── reports/        # Salida de los escaneos
```

## Instalación
```bash
pip install -r requirements.txt
```

## Uso
Para iniciar el dashboard:
```bash
streamlit run app.py
```
