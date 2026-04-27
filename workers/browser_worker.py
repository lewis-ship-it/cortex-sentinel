
import asyncio
import logging
import json
from playwright.async_api import async_playwright

from workers.base_worker import worker_loop, push_log
from task_queue.queues import BROWSER_QUEUE
from core.pipeline import on_scan_complete
from core.session_store import get_session

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def browser_scan(job_id, target_url, tier="Basic"):
    findings = []
    session = get_session(job_id)

    # TIER GATE: Basic users get 5s; Pro gets 15s. 
    # Your original 10s is a good middle ground, but branching saves resources.
    timeout = 5000 if tier == "Basic" else 15000

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()

        # YOUR ORIGINAL LOGIC: Preserve session/cookie handling
        if session:
            try:
                domain = target_url.split("/")[2]
                cookies = [{
                    "name": k,
                    "value": v,
                    "domain": domain,
                    "path": "/"
                } for k, v in session.get("cookies", {}).items()]
                if cookies:
                    await context.add_cookies(cookies)
            except Exception as e:
                push_log(job_id, f"[BROWSER] Session setup error: {str(e)}", tier=tier)

        page = await context.new_page()

        try:
            # Navigate with tiered timeout
            await page.goto(target_url, timeout=timeout)

            # --- ACTIVE DETECTIONS (PRO ONLY) ---
            if tier == "Professional":
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
            else:
                push_log(job_id, "[BROWSER] Skipping active DOM injection (Pro Feature)", tier=tier)

            # --- PASSIVE DISCOVERY (TIERED LIMITS) ---
            links = await page.eval_on_selector_all("a", "els => els.map(e => e.href)")
            
            # Limit Basic users to 10 links to prevent massive downstream task queues
            link_limit = 10 if tier == "Basic" else 500
            
            for link in links[:link_limit]:
                findings.append({
                    "type": "Discovered Endpoint",
                    "target_url": link,
                    "severity": "Info",
                    "confidence": 1.0
                })

        except Exception as e:
            push_log(job_id, f"[BROWSER] Scan interrupted: {str(type(e).__name__)}", tier=tier)
        finally:
            await browser.close()

    return findings

def handle(job):
    # Retrieve job_id and target_url from your uploaded version
    job_id = job["job_id"]
    # Use .get() to provide a fallback or log a clear error
    target_url = job.get("target_url") or job.get("url")

    if not target_url:
        logging.error(f"[WORKER] Job missing target_url: {job.get('job_id')}")
        return # Gracefully exit instead of crashing
        
    # Retrieve tier from my base_worker refactor (defaults to Basic)
    tier = job.get("tier", "Basic")

    push_log(job_id, f"[BROWSER] Starting {tier} scan for {target_url}", tier=tier)

    # Execute the merged scan logic
    findings = asyncio.run(browser_scan(job_id, target_url, tier=tier))

    push_log(job_id, f"[BROWSER] Found {len(findings)} items", tier=tier)

    # Hand off to the pipeline
    on_scan_complete(job_id, findings)

if __name__ == "__main__":
    worker_loop(BROWSER_QUEUE, handle)

