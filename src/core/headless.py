from playwright.async_api import async_playwright
import asyncio

class HeadlessScanner:
    async def scan_dom_xss(self, url):
        """
        Scans a URL for DOM-based XSS by fuzzing inputs.
        Returns a list of findings.
        """
        findings = []
        print(f"[*] Starting Headless Scan on {url}")
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Intercept dialogs (alert/confirm/prompt)
                page.on("dialog", lambda dialog: self._handle_dialog(dialog, url, findings))
                
                try:
                    await page.goto(url, wait_until="networkidle", timeout=10000)
                except Exception:
                    pass # Continue even if timeout

                # 1. URL Fragment Test
                payload = "<img src=x onerror=alert(1)>"
                await page.goto(f"{url}#{payload}", wait_until="networkidle")
                
                # 2. Input Fuzzing
                # Find all visible inputs
                inputs = await page.locator("input:visible, textarea:visible").all()
                print(f"[*] Found {len(inputs)} inputs to fuzz in headless mode.")
                
                for i, input_el in enumerate(inputs):
                    try:
                        # Clear and type payload
                        await input_el.fill(payload)
                        await input_el.press("Enter")
                        # Wait a bit for JS to react
                        await page.wait_for_timeout(500)
                    except Exception as e:
                        # print(f"[-] Error fuzzing input {i}: {e}")
                        pass

                await browser.close()
                
        except Exception as e:
            print(f"[-] Headless error: {e}")
            
        return findings

    def _handle_dialog(self, dialog, url, findings):
        print(f"[!] DOM XSS Alert Triggered: {dialog.message}")
        findings.append({
            "type": "DOM XSS (Headless)",
            "url": url,
            "payload": "alert(1)",
            "evidence": f"Dialog triggered: {dialog.message}"
        })
        asyncio.create_task(dialog.dismiss())
