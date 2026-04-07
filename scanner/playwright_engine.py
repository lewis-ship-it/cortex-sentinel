import asyncio
import logging

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logging.warning("[PLAYWRIGHT] playwright not installed. Browser scanning disabled.")


class PlaywrightScanner:
    """
    Headless browser scanner for DOM-based XSS and JS-rendered content.
    """

    def __init__(self):
        self.xss_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
        ]

    async def scan(self, url):
        """
        Returns (findings, endpoints) tuple.
        findings: list of vulnerability dicts
        endpoints: list of discovered URLs
        """
        if not PLAYWRIGHT_AVAILABLE:
            logging.warning("[PLAYWRIGHT] Skipping browser scan - playwright not available.")
            return [], []

        findings = []
        endpoints = set()

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                await page.goto(url, timeout=15000)

                # Collect all links visible after JS renders
                links = await page.eval_on_selector_all(
                    "a[href]",
                    "els => els.map(e => e.href)"
                )
                endpoints.update(links)

                # Test XSS via URL param injection
                for payload in self.xss_payloads:
                    test_url = f"{url}?q={payload}"
                    try:
                        await page.goto(test_url, timeout=10000)
                        content = await page.content()
                        if payload in content:
                            findings.append({
                                "type": "DOM XSS",
                                "url": test_url,
                                "payload": payload,
                                "severity": "High",
                                "confidence": 0.75,
                                "evidence": payload
                            })
                    except Exception:
                        pass

                await browser.close()

        except Exception as e:
            logging.error(f"[PLAYWRIGHT ERROR] {url} -> {e}")

        return findings, list(endpoints)