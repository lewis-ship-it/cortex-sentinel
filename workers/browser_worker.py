import asyncio
from playwright.async_api import async_playwright

from workers.base_worker import worker_loop, push_log
from task_queue.queues import BROWSER_QUEUE
from core.pipeline import on_scan_complete
from core.session_store import get_session


async def browser_scan(job_id, target_url):
    findings = []
    session = get_session(job_id)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()

        if session:
            domain = target_url.split("/")[2]
            cookies = [{
                "name": k,
                "value": v,
                "domain": domain,
                "path": "/"
            } for k, v in session.get("cookies", {}).items()]
            if cookies:
                await context.add_cookies(cookies)

        page = await context.new_page()

        try:
            await page.goto(target_url, timeout=10000)

            payload = "<script>window.__xss_flag=1</script>"
            await page.evaluate(f"document.body.innerHTML += `{payload}`;")

            if await page.evaluate("window.__xss_flag") == 1:
                findings.append({
                    "type": "DOM XSS",
                    "target_url": target_url,
                    "payload": payload,
                    "severity": "Critical",
                    "confidence": 0.9
                })

            links = await page.eval_on_selector_all("a", "els => els.map(e => e.href)")
            for l in links:
                findings.append({
                    "type": "Discovered Endpoint",
                    "target_url": l,
                    "severity": "Info",
                    "confidence": 1.0
                })

        except Exception:
            pass

        await browser.close()

    return findings


def handle(job):
    job_id = job["job_id"]
    target_url = job["target_url"]

    push_log(job_id, f"[BROWSER] {target_url}")

    findings = asyncio.run(browser_scan(job_id, target_url))

    push_log(job_id, f"[BROWSER] Found {len(findings)}")

    on_scan_complete(job_id, findings)


if __name__ == "__main__":
    worker_loop(BROWSER_QUEUE, handle)