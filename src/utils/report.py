from fpdf import FPDF
import datetime

class ReportGenerator(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Web Vulnerability Scan Report', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def generate(self, results, filename="report.pdf"):
        self.add_page()
        self.set_auto_page_break(auto=True, margin=15)
        self.set_font('Arial', '', 12)
        
        self.cell(0, 10, f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
        self.ln(10)
        
        if not results:
            self.cell(0, 10, "No vulnerabilities found.", 0, 1)
        else:
            self.set_font('Arial', 'B', 12)
            self.cell(0, 10, f"Found {len(results)} vulnerabilities:", 0, 1)
            self.ln(5)
            
            for i, vuln in enumerate(results, 1):
                self.set_font('Arial', 'B', 11)
                self.cell(0, 10, f"{i}. {vuln['type']}", 0, 1)
                
                self.set_font('Arial', '', 10)
                # Use effective page width provided by fpdf2
                width = self.epw
                
                self.multi_cell(width, 8, f"URL: {vuln['url']}")
                self.multi_cell(width, 8, f"Field: {vuln['field']}")
                self.multi_cell(width, 8, f"Payload: {vuln['payload']}")
                if 'evidence' in vuln:
                    self.multi_cell(width, 8, f"Evidence: {vuln['evidence']}")
                self.ln(5)
                
        self.output(filename)
        return filename
