# workers/browser_verification_worker.py
import asyncio
from playwright.async_api import async_playwright
from task_queue.redis_client import pop, push
from task_queue.queues import BROWSER_QUEUE, AGGREGATION_QUEUE
from scanner.ai_brain import AIBrain # Back in

brain = AIBrain()

async def verify_dom_execution(job):
    url = job.get("url")
    payload = job.get("payload")
    auth = job.get("auth") # Handling your auth config

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        # Context can handle cookies/auth if needed
        context = await browser.new_context() 
        page = await context.new_page()
        
        executed = False
        page.on("dialog", lambda d: globals().update(executed=True) or d.dismiss())
        
        try:
            await page.goto(url, timeout=10000)
            await asyncio.sleep(2)
        except: pass
        
        await browser.close()
        return executed

async def main():
    while True:
        job = pop(BROWSER_QUEUE)
        if job:
            # 1. First, use your AIBrain for a quick sanity check
            if await brain.is_plausible(job):
                # 2. Then, do the expensive browser execution
                if await verify_dom_execution(job):
                    push(AGGREGATION_QUEUE, job)
        await asyncio.sleep(1)