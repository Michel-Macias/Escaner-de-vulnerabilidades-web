from src.utils.report import ReportGenerator
import os

# Dummy data
results = [
    {
        "type": "SQL Injection",
        "url": "http://example.com/vuln",
        "field": "id",
        "payload": "' OR 1=1 --",
        "evidence": "Syntax error in SQL statement"
    },
    {
        "type": "XSS",
        "url": "http://example.com/search",
        "field": "q",
        "payload": "<script>alert(1)</script>",
        "evidence": "Alert box popped up"
    }
]

# Generate report
report_gen = ReportGenerator()
filename = "test_report.pdf"
report_gen.generate(results, filename)

print(f"Generated {filename}")
