# scanner/playwright_engine.py

import asyncio
from playwright.async_api import async_playwright
import logging
from urllib.parse import urlparse

class PlaywrightScanner:

    def __init__(self):
        self.xss_payload = "<script>alert(1)</script>"

    async def scan(self, url, auth_config=None):
        findings = []
        endpoints = set()

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # -----------------------
                # AUTH HANDLING
                # -----------------------
                if auth_config:
                    try:
                        if auth_config.get("type") == "login":
                            await page.goto(auth_config.get("login_url"))

                            await page.fill('input[name="username"]', auth_config.get("username", ""))
                            await page.fill('input[name="password"]', auth_config.get("password", ""))

                            await page.click("button[type=submit]")
                            await page.wait_for_load_state("networkidle")

                            logging.info("[PLAYWRIGHT] Logged in")

                        elif auth_config.get("type") == "cookie":
                            domain = urlparse(url).netloc

                            cookies = [
                                {
                                    "name": k,
                                    "value": v,
                                    "domain": domain,
                                    "path": "/"
                                }
                                for k, v in auth_config.get("cookies", {}).items()
                            ]

                            await context.add_cookies(cookies)
                            logging.info("[PLAYWRIGHT] Cookies injected")

                    except Exception as e:
                        logging.error(f"[PLAYWRIGHT AUTH ERROR] {e}")

                # -----------------------
                # NETWORK LISTENER
                # -----------------------
                def handle_request(request):
                    endpoints.add(request.url)

                page.on("request", handle_request)

                # -----------------------
                # LOAD PAGE
                # -----------------------
                await page.goto(url, timeout=20000)
                await page.wait_for_load_state("networkidle")

                logging.info(f"[PLAYWRIGHT] Loaded {url}")

                # -----------------------
                # DOM XSS TEST
                # -----------------------
                await page.evaluate(f"""
                    (() => {{
                        let inputs = document.querySelectorAll('input, textarea');
                        inputs.forEach(i => i.value = `{self.xss_payload}`);
                    }})();
                """)

                # try to trigger events
                await page.keyboard.press("Enter")
                await page.wait_for_timeout(2000)

                content = await page.content()

                if self.xss_payload in content:
                    findings.append({
                        "type": "DOM XSS",
                        "url": url,
                        "severity": "Critical",
                        "description": "Payload reflected in DOM after JS execution"
                    })
                    logging.warning(f"[PLAYWRIGHT] DOM XSS detected at {url}")

            except Exception as e:
                logging.error(f"[PLAYWRIGHT ERROR] {e}")

            finally:
                await browser.close()

        return findings, list(endpoints)