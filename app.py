import streamlit as st
import pandas as pd
from src.core.crawler import Crawler
from src.modules.sqli import SQLInjection
from src.modules.xss import XSS
from src.modules.html_inj import HTMLInjection
from src.modules.cmd_inj import CommandInjection
from src.modules.ldap import LDAPInjection
from src.utils.report import ReportGenerator
import os

st.set_page_config(page_title="Web Vuln Scanner", layout="wide")

st.title("🛡️ Web Application Vulnerability Scanner")
st.markdown("### Professional Security Testing Tool")

# Sidebar Configuration
st.sidebar.header("Configuration")
target_url = st.sidebar.text_input("Target URL", "http://testphp.vulnweb.com")

st.sidebar.subheader("Scan Modules")
use_sqli = st.sidebar.checkbox("SQL Injection", True)
use_xss = st.sidebar.checkbox("XSS (Cross-Site Scripting)", True)
use_html = st.sidebar.checkbox("HTML Injection", True)
use_cmd = st.sidebar.checkbox("Command Injection", True)
use_ldap = st.sidebar.checkbox("LDAP Injection", False)

if st.sidebar.button("Start Scan"):
    if not target_url:
        st.error("Please enter a valid URL.")
    else:
        st.info(f"Starting crawl on {target_url}...")
        
        # Initialize Crawler
        crawler = Crawler(target_url)
        
        # Progress Bar
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Crawl
        status_text.text("Crawling website...")
        visited_urls, forms = crawler.run()
        progress_bar.progress(30)
        
        st.success(f"Crawl finished. Found {len(visited_urls)} URLs and {len(forms)} forms.")
        
        # Initialize Modules
        modules = []
        if use_sqli: modules.append(SQLInjection(crawler.requester))
        if use_xss: modules.append(XSS(crawler.requester))
        if use_html: modules.append(HTMLInjection(crawler.requester))
        if use_cmd: modules.append(CommandInjection(crawler.requester))
        if use_ldap: modules.append(LDAPInjection(crawler.requester))
        
        all_results = []
        
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

st.markdown("---")
st.markdown("© 2025 Web Vuln Scanner Project - Educational Use Only")
