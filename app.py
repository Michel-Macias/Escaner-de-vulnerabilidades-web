import logging
import os
import re
from urllib.parse import urlparse

import pandas as pd
import requests
import streamlit as st

from src.core.crawler import Crawler
from src.modules.sqli import SQLInjection
from src.modules.xss import XSS
from src.modules.html_inj import HTMLInjection
from src.modules.cmd_inj import CommandInjection
from src.modules.ldap import LDAPInjection
from src.utils.report import ReportGenerator
from src.utils.user_guide_content import get_user_guide_markdown

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def validate_target_url(url: str) -> tuple[bool, str]:
    """Validación básica de URL de destino para uso en auditoría autorizada."""
    if not url or not url.strip():
        return False, "URL vacía."

    pattern = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
    if not pattern.match(url.strip()):
        return False, "Esquema inválido. La URL debe empezar por http:// o https://."

    parsed = urlparse(url.strip())
    if parsed.hostname in (None, "", "localhost") and parsed.port not in (None, 80, 443):
        return False, "Host inválido en la URL."

    if "@" in parsed.netloc:
        return False, "La URL contiene credenciales inline. Usa formularios de login del scanner."

    return True, "OK"


def sanitize_severity_metric_label(label: str) -> str:
    # Placeholder por si más adelante añadimos campo severity en hallazgos.
    return label

st.set_page_config(page_title="Web Vuln Scanner", layout="wide")

# --- BLOQUE DE SEGURIDAD (OSINT REMEDIATION) ---
def check_password():
    """Retorna True si el usuario tiene la contraseña correcta."""

    if "APP_PASSWORD" not in st.secrets:
        st.error("⚠️ Error de configuración: Falta el secreto APP_PASSWORD. Configúralo en .streamlit/secrets.toml (local) o en el dashboard (nube).")
        return False

    def password_entered():
        if st.session_state["password"] == st.secrets["APP_PASSWORD"]:
            st.session_state["password_correct"] = True
            del st.session_state["password"]  # Borrar clave de memoria por seguridad
        else:
            st.session_state["password_correct"] = False

    if "password_correct" not in st.session_state:
        # Primera ejecución, mostrar input
        st.text_input(
            "🔒 Esta es una herramienta privada. Introduce la contraseña:",
            type="password",
            on_change=password_entered,
            key="password"
        )
        return False
    elif not st.session_state["password_correct"]:
        # Contraseña incorrecta
        st.text_input(
            "🔒 Esta es una herramienta privada. Introduce la contraseña:",
            type="password",
            on_change=password_entered,
            key="password"
        )
        st.error("⛔ Contraseña incorrecta")
        return False
    else:
        # Contraseña correcta
        return True

if not check_password():
    st.stop()  # DETIENE TODA LA EJECUCIÓN AQUÍ SI NO HAY CLAVE
# -----------------------------------------------

st.title("🛡️ Web Application Vulnerability Scanner")
st.markdown("### Professional Security Testing Tool")

# Sidebar Navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Scanner", "User Guide"])

def show_user_guide():
    st.markdown(get_user_guide_markdown())

def show_scanner():
    # Sidebar Configuration
    st.sidebar.header("Configuration")
    target_url = st.sidebar.text_input("Target URL", "")
    st.sidebar.caption("Ejemplo: http://localhost:8081 o http://testphp.vulnweb.com")

    # Validación previa para UX y seguridad operacional
    if target_url.strip():
        ok, reason = validate_target_url(target_url)
        if not ok:
            st.sidebar.error(reason)

    st.sidebar.subheader("Authentication (Optional)")
    enable_auth = st.sidebar.checkbox("Enable Login")
    if enable_auth:
        login_url = st.sidebar.text_input("Login URL", "http://localhost:8081/login.php")
        username = st.sidebar.text_input("Username", "")
        password = st.sidebar.text_input("Password", "", type="password")

    st.sidebar.subheader("Stealth Mode")
    use_stealth = st.sidebar.checkbox("Enable Stealth")
    delay = 0.0
    proxies = []
    if use_stealth:
        delay = st.sidebar.slider("Request Delay (sec)", 0.0, 5.0, 1.0)
        proxy_list = st.sidebar.text_area("Proxies (one per line)", "")
        if proxy_list:
            proxies = proxy_list.split("\n")

    st.sidebar.subheader("Scan Modules")
    use_sqli = st.sidebar.checkbox("SQL Injection", True)
    use_xss = st.sidebar.checkbox("XSS (Cross-Site Scripting)", True)
    use_html = st.sidebar.checkbox("HTML Injection", True)
    use_cmd = st.sidebar.checkbox("Command Injection", True)
    use_ldap = st.sidebar.checkbox("LDAP Injection", False)
    use_headless = st.sidebar.checkbox("Headless DOM XSS (Slow)", False)

    st.sidebar.subheader("Crawl Limits")
    max_urls = st.sidebar.slider("Max URLs", 20, 500, 200, step=10)
    max_depth = st.sidebar.slider("Max Depth", 1, 5, 2)

    # Estado de escaneo para poder cancelar y persistir entre rerender
    if "scan_running" not in st.session_state:
        st.session_state["scan_running"] = False

    col1, col2 = st.sidebar.columns(2)
    with col1:
        start_disabled = st.session_state["scan_running"]
        start = st.button("Start Scan", disabled=start_disabled, type="primary")
    with col2:
        stop_disabled = not st.session_state["scan_running"]
        stop = st.button("Stop", disabled=stop_disabled)

    if stop:
        st.session_state["scan_running"] = False
        st.info("Deteniendo escaneo...")

    if start:
        if not target_url or not target_url.strip():
            st.error("Please enter a valid URL.")
        else:
            ok, reason = validate_target_url(target_url)
            if not ok:
                st.error(f"URL no válida: {reason}")
            else:
                st.info(f"Starting crawl on {target_url}...")

            # Initialize Crawler
            crawler = Crawler(target_url, max_urls=max_urls, max_depth=max_depth)
            # Apply Stealth
            if use_stealth:
                crawler.requester.delay = delay
                crawler.requester.proxies = proxies

            # Handle Authentication
            if enable_auth:
                from src.core.auth import LoginManager
                login_manager = LoginManager(crawler.requester)
                status_text = st.empty()
                status_text.text("Attempting login...")
                if login_manager.login(login_url, username, password):
                    st.success("Login successful! Scanning as authenticated user.")
                    # Pass cookies to async session
                    crawler.cookies = crawler.requester.session.cookies.get_dict()
                else:
                    st.error("Login failed! Continuing as anonymous...")

            # Progress and control
            progress_bar = st.progress(0)
            status_text = st.empty()
            st.session_state["scan_running"] = True

            # Crawl
            status_text.text("Crawling website (Async)...")
            import asyncio
            visited_urls, forms = asyncio.run(crawler.run())
            progress_bar.progress(30)

            st.success(f"Crawl finished. Found {len(visited_urls)} URLs and {len(forms)} forms.")

            all_results = []

            # Fingerprinting
            status_text.text("Fingerprinting target...")
            from src.modules.fingerprint import Fingerprinter
            fingerprinter = Fingerprinter(crawler.requester)
            tech_findings = fingerprinter.scan(target_url)
            all_results.extend(tech_findings)

            # Initialize Modules
            modules = []
            if use_sqli: modules.append(SQLInjection(crawler.requester))
            if use_xss: modules.append(XSS(crawler.requester))
            if use_html: modules.append(HTMLInjection(crawler.requester))
            if use_cmd: modules.append(CommandInjection(crawler.requester))
            if use_ldap: modules.append(LDAPInjection(crawler.requester))

            # Scan Forms
            total_forms = len(forms)
            if total_forms > 0:
                for i, form in enumerate(forms):
                    if not st.session_state.get("scan_running", True):
                        break
                    status_text.text(f"Scanning form {i+1}/{total_forms} at {form['action']}")

                    for module in modules:
                        if not st.session_state.get("scan_running", True):
                            break
                        vulns = module.scan(form)
                        all_results.extend(vulns)

                    # Update progress (30% to 100%)
                    progress = 30 + int((i+1) / total_forms * 70)
                    progress_bar.progress(progress)
            else:
                st.warning("No forms found to scan.")
                progress_bar.progress(100)

            # Headless Scan
            if use_headless and st.session_state.get("scan_running", True):
                status_text.text("Running Headless DOM XSS Scan...")
                from src.core.headless import HeadlessScanner
                headless = HeadlessScanner()
                # Run headless scan on the target URL
                dom_vulns = asyncio.run(headless.scan_dom_xss(target_url))
                all_results.extend(dom_vulns)

            status_text.text("Scan completed!")
            st.session_state["scan_running"] = False

            # Display Results
            st.subheader("Scan Results")
            if all_results:
                # Normalizar hallazgos que puedan faltar columnas
                expected = {
                    "type", "url", "payload", "field", "severity", "evidence", "remediation"
                }
                normalized = []
                for item in all_results:
                    normalized.append({k: item.get(k, "") for k in expected})
                df = pd.DataFrame(normalized)

                with st.expander("Raw findings", expanded=False):
                    st.dataframe(df, use_container_width=True)

                high = sum(1 for v in all_results if v.get("severity") == "High" or v.get("severity") == "Critical")
                medium = sum(1 for v in all_results if v.get("severity") == "Medium")
                low = sum(1 for v in all_results if v.get("severity") == "Low")
                total = len(all_results)

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Vulnerabilities", total)
                col2.metric("High / Critical", high)
                col3.metric("Medium", medium)
                col4.metric("Low", low)

                if high or medium:
                    top = []
                    for v in all_results:
                        sev = v.get("severity", "Low")
                        if sev in ("High", "Critical"):
                            top.append(f"- `{v.get('type')}` en `{v.get('url')}` [{v.get('field')}]")
                    st.warning("Top findings:\n" + "\n".join(top[:10]))

                # Generate Report
                report_gen = ReportGenerator()
                report_file = report_gen.generate(all_results, "scan_report.pdf")

                with open(report_file, "rb") as pdf:
                    st.download_button(
                        label="Download PDF Report",
                        data=pdf,
                        file_name="scan_report.pdf",
                        mime="application/pdf",
                    )
            else:
                st.success("No vulnerabilities found! (Or maybe the scanner needs more power 😉)")
            st.session_state["scan_running"] = False

if page == "Scanner":
    show_scanner()
elif page == "User Guide":
    show_user_guide()

st.markdown("---")
st.markdown("© 2025 Web Vuln Scanner Project - Educational Use Only")
