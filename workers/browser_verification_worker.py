# workers/browser_verification_worker.py
import asyncio
from playwright.async_api import async_playwright
from task_queue.redis_client import pop, push
from task_queue.queues import BROWSER_QUEUE, AGGREGATION_QUEUE
from workers.base_worker import push_log  # Use the standard logger we set up
from scanner.ai_brain import AIBrain 

brain = AIBrain()

async def verify_dom_execution(job, tier="Basic"):
    """
    Performs the actual browser-based verification of a finding.
    Gated by tier to save resources.
    """
    url = job.get("url")
    payload = job.get("payload")
    auth = job.get("auth") 
    job_id = job.get("job_id", "unknown")

    # PRODUCTION GUARD: Basic users skip the browser execution entirely.
    # This is your biggest resource saver.
    if tier == "Basic":
        push_log(job_id, "[VERIFY] Basic Tier: Skipping browser verification to save resources.", tier=tier)
        return False 

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context() 
        page = await context.new_page()
        
        # SENIOR FIX: Using a local dictionary instead of globals() 
        # to ensure thread-safety during concurrent scans.
        state = {"executed": False}
        
        # Listen for the alert/dialog triggered by the XSS payload
        page.on("dialog", lambda d: state.update(executed=True) or d.dismiss())
        
        try:
            push_log(job_id, f"[VERIFY] Pro Tier: Executing browser verification for {url}", tier=tier)
            # Standard production timeout
            await page.goto(url, timeout=10000)
            # Wait a moment for async scripts to trigger the dialog
            await asyncio.sleep(2)
        except Exception as e:
            push_log(job_id, f"[VERIFY] Browser Error: {str(type(e).__name__)}", tier=tier)
        
        await browser.close()
        return state["executed"]

async def main():
    print("[WORKER] Browser Verification Worker started. Listening for tasks...")
    while True:
        # We use pop to pull from the Redis queue
        job = pop(BROWSER_QUEUE)
        
        if job:
            job_id = job.get("job_id", "unknown")
            tier = job.get("tier", "Basic") # From our base_worker setup

            # 1. TIER GATE: AI Sanity Check (Pro Only)
            if tier == "Professional":
                push_log(job_id, "[VERIFY] Running AI plausibility check...", tier=tier)
                if await brain.is_plausible(job):
                    # 2. PRO ONLY: Expensive browser execution
                    is_verified = await verify_dom_execution(job, tier=tier)
                    
                    if is_verified:
                        push_log(job_id, "[VERIFY] AI + Browser confirmed finding. Promoting to Aggregator.", tier=tier)
                        job["verified"] = True
                        push(AGGREGATION_QUEUE, job)
                    else:
                        push_log(job_id, "[VERIFY] Verification failed. Finding discarded.", tier=tier)
                else:
                    push_log(job_id, "[VERIFY] AI flagged finding as implausible. Skipping.", tier=tier)
            
            else:
                # BASIC TIER: Skip AI and Browser. 
                # We pass the finding through "as-is" to keep the system fast.
                push_log(job_id, "[VERIFY] Basic Tier: Passing finding without AI verification.", tier=tier)
                job["verified"] = False
                push(AGGREGATION_QUEUE, job)
        
        # Prevent CPU spinning
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass