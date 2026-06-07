import logging
from playwright.async_api import async_playwright
import asyncio

from src.core.extractor import FormExtractor
from src.modules.xss import XSS

logger = logging.getLogger(__name__)


class HeadlessScanner:
    async def scan_dom_xss(self, url, *, requester=None, max_inputs=20):
        """
        Scans a URL for DOM-based XSS by fuzzing inputs with a Playwright Chromium.
        """
        findings = []
        extractor = FormExtractor()
        logger.info("[*] Headless scan on %s", url)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                # Intercept dialogs (alert/confirm/prompt)
                page.on("dialog", lambda dialog: self._handle_dialog(dialog, url, findings))

                try:
                    await page.goto(url, wait_until="networkidle", timeout=10000)
                except Exception:
                    pass

                # 1. URL Fragment Test
                payload = "<img src=x onerror=alert(1)>"
                try:
                    await page.goto(f"{url}#{payload}", wait_until="networkidle")
                except Exception:
                    pass

                # 2. Input Fuzzing
                inputs = await page.locator("input:visible, textarea:visible").all()
                inputs = inputs[:max_inputs]
                logger.info("[*] Headless fuzzing %s inputs", len(inputs))

                for i, input_el in enumerate(inputs, 1):
                    try:
                        tag_name = await input_el.evaluate("el => el.tagName")
                        type_val = await input_el.evaluate("el => (el.type || '').toLowerCase()")
                        if (tag_name == "INPUT" and type_val in ("submit", "button", "reset")) or (tag_name == "TEXTAREA" and type_val in ("hidden", "file")):
                            continue
                        await input_el.fill(payload)
                        await input_el.press("Enter")
                        try:
                            await page.wait_for_timeout(300)
                        except Exception:
                            pass
                    except Exception as e:
                        logger.debug("Headless error input %s: %s", i, e)

                try:
                    await browser.close()
                except Exception:
                    pass
        except Exception as e:
            logger.error("Headless error: %s", e)

        return findings

    @staticmethod
    def _handle_dialog(dialog, url, findings):
        try:
            findings.append({
                "type": "DOM XSS (Headless)",
                "url": url,
                "payload": "alert(1)",
                "field": "URL/Input",
                "severity": "Medium",
                "evidence": f"Dialog triggered: {dialog.message}",
                "remediation": "Sanitiza datos antes de inyectarlos en sinks DOM (innerHTML, location, eval).",
            })
            logger.warning("[!] DOM XSS Alert Triggered: %s", dialog.message)
        except Exception:
            pass
        try:
            asyncio.get_running_loop().create_task(dialog.dismiss())
        except RuntimeError:
            pass
