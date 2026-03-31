# scanner/playwright_engine.py

import asyncio
from playwright.async_api import async_playwright
import logging

class PlaywrightScanner:

    def __init__(self):
        self.xss_payload = "<script>alert(1)</script>"

    async def scan(self, url, auth_config=None):
        findings = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            # -----------------------
            # AUTH HANDLING
            # -----------------------
            if auth_config:
                if auth_config.get("type") == "login":
                    await page.goto(auth_config["login_url"])

                    await page.fill('input[name="username"]', auth_config["username"])
                    await page.fill('input[name="password"]', auth_config["password"])

                    await page.click("button[type=submit]")
                    await page.wait_for_load_state("networkidle")

                    logging.info("[PLAYWRIGHT] Logged in")

                elif auth_config.get("type") == "cookie":
                    cookies = [
                        {
                            "name": k,
                            "value": v,
                            "domain": url.split("//")[1]
                        }
                        for k, v in auth_config["cookies"].items()
                    ]
                    await context.add_cookies(cookies)

            # -----------------------
            # NETWORK LISTENER (API DISCOVERY)
            # -----------------------
            endpoints = set()

            def handle_request(request):
                endpoints.add(request.url)

            page.on("request", handle_request)

            # -----------------------
            # LOAD PAGE
            # -----------------------
            await page.goto(url)
            await page.wait_for_load_state("networkidle")

            logging.info(f"[PLAYWRIGHT] Loaded {url}")

            # -----------------------
            # DOM XSS TEST
            # -----------------------
            await page.evaluate(f"""
                let inputs = document.querySelectorAll('input, textarea');
                inputs.forEach(i => i.value = `{self.xss_payload}`);
            """)

            await page.keyboard.press("Enter")
            await page.wait_for_timeout(2000)

            content = await page.content()

            if self.xss_payload in content:
                findings.append({
                    "type": "DOM XSS",
                    "url": url,
                    "severity": "Critical"
                })
                logging.warning(f"[PLAYWRIGHT] DOM XSS detected at {url}")

            # -----------------------
            # RETURN DISCOVERED ENDPOINTS
            # -----------------------
            browser.close()

        return findings, list(endpoints)