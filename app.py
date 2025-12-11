import streamlit as st
import pandas as pd
from src.core.crawler import Crawler
from src.modules.sqli import SQLInjection
from src.modules.xss import XSS
from src.modules.html_inj import HTMLInjection
from src.modules.cmd_inj import CommandInjection
from src.modules.ldap import LDAPInjection
from src.utils.report import ReportGenerator
from src.utils.user_guide_content import get_user_guide_markdown
import os

st.set_page_config(page_title="Web Vuln Scanner", layout="wide")

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
    target_url = st.sidebar.text_input("Target URL", "http://localhost:8081")

    st.sidebar.subheader("Authentication (Optional)")
    enable_auth = st.sidebar.checkbox("Enable Login")
    if enable_auth:
        login_url = st.sidebar.text_input("Login URL", "http://localhost:8081/login.php")
        username = st.sidebar.text_input("Username", "admin")
        password = st.sidebar.text_input("Password", "password", type="password")

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

    if st.sidebar.button("Start Scan"):
        if not target_url:
            st.error("Please enter a valid URL.")
        else:
            st.info(f"Starting crawl on {target_url}...")
            
            # Initialize Crawler
            crawler = Crawler(target_url)
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
                    # TODO: Pass cookies to async session if needed
                else:
                    st.error("Login failed! Continuing as anonymous...")
            
            # Progress Bar
            progress_bar = st.progress(0)
            status_text = st.empty()
            
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
            
            # Scan Forms
            total_forms = len(forms)
            if total_forms > 0:
                for i, form in enumerate(forms):
                    status_text.text(f"Scanning form {i+1}/{total_forms} at {form['action']}")
                    
                    for module in modules:
                        vulns = module.scan(form)
                        all_results.extend(vulns)
                    
                    # Update progress (30% to 100%)
                    progress = 30 + int((i+1) / total_forms * 70)
                    progress_bar.progress(progress)
            else:
                st.warning("No forms found to scan.")
                progress_bar.progress(100)

            # Headless Scan
            if use_headless:
                status_text.text("Running Headless DOM XSS Scan...")
                from src.core.headless import HeadlessScanner
                headless = HeadlessScanner()
                # Run headless scan on the target URL (and maybe discovered links)
                # For demo, just the target
                dom_vulns = asyncio.run(headless.scan_dom_xss(target_url))
                all_results.extend(dom_vulns)

            status_text.text("Scan completed!")
            
            # Display Results
            st.subheader("Scan Results")
            if all_results:
                df = pd.DataFrame(all_results)
                st.dataframe(df)
                
                # Severity Metrics (Mock logic for demo)
                col1, col2, col3 = st.columns(3)
                col1.metric("Total Vulnerabilities", len(all_results))
                col2.metric("High Severity", len([v for v in all_results if "SQL" in v['type'] or "Command" in v['type']]))
                col3.metric("Medium Severity", len([v for v in all_results if "XSS" in v['type']]))
                
                # Generate Report
                report_gen = ReportGenerator()
                report_file = report_gen.generate(all_results, "scan_report.pdf")
                
                with open(report_file, "rb") as pdf:
                    st.download_button(
                        label="Download PDF Report",
                        data=pdf,
                        file_name="scan_report.pdf",
                        mime="application/pdf"
                    )
            else:
                st.success("No vulnerabilities found! (Or maybe the scanner needs more power 😉)")

if page == "Scanner":
    show_scanner()
elif page == "User Guide":
    show_user_guide()

st.markdown("---")
st.markdown("© 2025 Web Vuln Scanner Project - Educational Use Only")
