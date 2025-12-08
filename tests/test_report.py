import unittest
import os
from src.utils.report import ReportGenerator

class TestReport(unittest.TestCase):
    def test_pdf_generation(self):
        results = [
            {
                "type": "SQL Injection",
                "url": "http://example.com/login",
                "payload": "' OR 1=1",
                "field": "username",
                "evidence": "syntax error"
            }
        ]
        
        generator = ReportGenerator()
        filename = "test_report.pdf"
        
        # Generate
        output_file = generator.generate(results, filename)
        
        # Check if file exists
        self.assertTrue(os.path.exists(output_file))
        self.assertTrue(os.path.getsize(output_file) > 0)
        
        # Cleanup
        os.remove(output_file)

if __name__ == "__main__":
    unittest.main()
