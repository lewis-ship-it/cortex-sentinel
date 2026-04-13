# workers/browser_worker.py
import asyncio
import logging
from urllib.parse import urlparse

from task_queue.redis_client import pop, push, retry
from task_queue.queues import BROWSER_QUEUE, AGGREGATION_QUEUE, SCAN_QUEUE
from scanner.browser.playwright_engine import PlaywrightScanner

logger = logging.getLogger(__name__)
browser = PlaywrightScanner()

def normalize_spa_endpoints(endpoints):
    """
    Prevents "Queue Bombing" by filtering out redundant routes.
    It replaces digits with '0' to group similar dynamic paths.
    Example: 
      - /api/v1/user/123 -> /api/v1/user/0
      - /api/v1/user/456 -> /api/v1/user/0 (Filtered out)
    """
    unique_patterns = set()
    normalized = []

    for url in endpoints:
        try:
            parsed = urlparse(url)
            path = parsed.path
            
            # Create a pattern by masking digits
            pattern = "".join([c if not c.isdigit() else "0" for c in path])
            
            # Key consists of domain + masked path pattern
            key = f"{parsed.netloc}{pattern}"
            
            if key not in unique_patterns:
                unique_patterns.add(key)
                normalized.append(url)
        except Exception:
            # If parsing fails, keep the original URL to be safe
            normalized.append(url)
            
    return normalized

async def main():
    logging.basicConfig(level=logging.INFO)
    logger.info("[BROWSER WORKER] Production Browser Engine Active...")

    while True:
        job = pop(BROWSER_QUEUE)
        if not job:
            await asyncio.sleep(1)
            continue

        job_id = job.get("job_id")
        url    = job.get("url")
        auth   = job.get("auth")

        try:
            logger.info(f"[BROWSER WORKER] Launching Playwright for: {url}")
            
            # 1. Execute the browser-based scan (DOM XSS + SPA Discovery)
            findings, spa_endpoints = await browser.scan(url)

            # 2. Handle confirmed DOM XSS findings immediately
            if findings:
                logger.info(f"[BROWSER WORKER] Confirmed {len(findings)} DOM XSS vulnerabilities.")
                push(AGGREGATION_QUEUE, {
                    "job_id": job_id,
                    "data":   {"findings": findings},
                })

            # 3. Normalize discovered endpoints before pushing to Active Scanner
            # This is the "Full-Proof" fix to prevent redundant scanning.
            filtered_endpoints = normalize_spa_endpoints(spa_endpoints)
            
            logger.info(
                f"[BROWSER WORKER] Discovery complete. Total: {len(spa_endpoints)} | "
                f"Queued for Active Scan: {len(filtered_endpoints)}"
            )

            # 4. Push unique endpoints to the SCAN_QUEUE
            for ep in filtered_endpoints:
                push(SCAN_QUEUE, {
                    "job_id": job_id,
                    "url":    ep,
                    "auth":   auth,
                })

        except Exception as e:
            logger.error(f"[BROWSER WORKER] Critical failure for {url}: {e}")
            retry(BROWSER_QUEUE, job, str(e))

if __name__ == "__main__":
    asyncio.run(main())