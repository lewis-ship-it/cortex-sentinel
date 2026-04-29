# workers/browser_verification.py
# ──────────────────────────────────────────────────────────────────────────────
# FIX — CPU-spinning busy-loop
#   Old code used non-blocking pop() + asyncio.sleep(0.1) in the main loop.
#   When the queue is empty this spins at 10 polls/second, burning CPU
#   continuously across all idle worker containers.
#
#   Fixed: replaced with blocking_pop(timeout=5) which blocks the connection
#   at the Redis server for up to 5 seconds before returning None.  The worker
#   uses virtually zero CPU while idle.
# ──────────────────────────────────────────────────────────────────────────────

import asyncio

from playwright.async_api import async_playwright

from task_queue.redis_client import blocking_pop, push
from task_queue.queues import BROWSER_QUEUE, AGGREGATION_QUEUE
from workers.base_worker import push_log
from scanner.ai_brain import AIBrain

brain = AIBrain()


async def verify_dom_execution(job: dict, tier: str = "Basic") -> bool:
    """
    Performs browser-based DOM verification of a finding.
    Professional tier only — Basic tier always returns False (skipped).
    """
    url     = job.get("url")
    job_id  = job.get("job_id", "unknown")

    if tier == "Basic":
        push_log(job_id, "[VERIFY] Basic tier: skipping browser verification", tier=tier)
        return False

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page    = await context.new_page()

        # Thread-safe state dict instead of globals
        state = {"executed": False}
        page.on("dialog", lambda d: state.update(executed=True) or d.dismiss())

        try:
            push_log(job_id, f"[VERIFY] Pro tier: browser verification for {url}", tier=tier)
            await page.goto(url, timeout=10_000)
            await asyncio.sleep(2)  # wait for async scripts
        except Exception as e:
            push_log(job_id, f"[VERIFY] Browser error: {type(e).__name__}", tier=tier)
        finally:
            await browser.close()

        return state["executed"]


async def main() -> None:
    print("[WORKER] Browser Verification Worker started — listening for tasks...")
    while True:
        # FIX: blocking_pop avoids the 0.1s CPU-spinning busy-loop
        job = blocking_pop(BROWSER_QUEUE, timeout=5)
        if not job:
            continue

        job_id = job.get("job_id", "unknown")
        tier   = job.get("tier", "Basic")

        if tier == "Professional":
            push_log(job_id, "[VERIFY] Running AI plausibility check...", tier=tier)
            if await brain.is_plausible(job):
                is_verified = await verify_dom_execution(job, tier=tier)
                if is_verified:
                    push_log(
                        job_id,
                        "[VERIFY] AI + browser confirmed finding — promoting to Aggregator",
                        tier=tier,
                    )
                    job["verified"] = True
                    push(AGGREGATION_QUEUE, job)
                else:
                    push_log(job_id, "[VERIFY] Browser verification failed — finding discarded", tier=tier)
            else:
                push_log(job_id, "[VERIFY] AI flagged finding as implausible — skipping", tier=tier)
        else:
            # Basic tier: pass through without AI or browser overhead
            push_log(job_id, "[VERIFY] Basic tier: passing finding without verification", tier=tier)
            job["verified"] = False
            push(AGGREGATION_QUEUE, job)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
