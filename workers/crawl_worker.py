# workers/crawl_worker.py
# ──────────────────────────────────────────────────────────────────────────────
# FIXES vs previous version:
#   1. on_crawl_complete(job_id, found_urls) was missing `tier` and `auth`
#      arguments — pipeline.on_crawl_complete requires them to push correct
#      payloads to SCAN_QUEUE and BROWSER_QUEUE.
#   2. crawl() used blocking requests.get() — replaced with httpx for async-
#      compatible timeouts and connection reuse; requests kept as sync fallback.
#   3. Added robots.txt parsing to seed crawler with disallowed paths
#      (common hidden admin/backup paths bug bounty hunters care about).
#   4. Added sitemap.xml parsing for deeper URL discovery.
#   5. Added subpath bruteforce for common high-value endpoints.
#   6. CRITICAL: Removed asyncio.run() which created a new event loop and
#      blocked the worker thread for 10+ minutes during deep crawls.
#   7. Added overall crawl timeout (120s Basic / 300s Professional) so jobs
#      never get stuck indefinitely on slow/unresponsive targets.
#   8. Fixed pipeline stall: on_crawl_complete now only pushes to SCAN_QUEUE.
#      Browser queue is handled separately and does not block the scan counter.
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import logging
import httpx
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re

from workers.base_worker import worker_loop, push_log
from task_queue.queues import CRAWL_QUEUE
from core.pipeline import on_crawl_complete
from core.orchestrator import handle_completion
from core.logger import get_logger
from task_queue.redis_client import log_event
from scanner.dast.crawler import Crawler
from scanner.js_parser import JSParser

logger = get_logger("crawl_worker")

# High-value paths to always probe (bug bounty goldmines)
HIGH_VALUE_PATHS = [
    "/admin", "/admin/", "/administrator", "/wp-admin", "/phpmyadmin",
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/swagger-ui",
    "/swagger.json", "/openapi.json", "/api-docs", "/.well-known",
    "/backup", "/backup.sql", "/dump.sql", "/.env", "/.git/HEAD",
    "/server-status", "/phpinfo.php", "/actuator", "/actuator/health",
    "/actuator/env", "/metrics", "/debug", "/console", "/shell",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/security.txt",
    "/login", "/register", "/signup", "/logout", "/auth", "/oauth",
    "/callback", "/forgot-password", "/reset-password",
    "/upload", "/uploads", "/files", "/static", "/assets",
]

BLOCKED_PATHS = ["/register", "/signup", "/auth/sign-up", "/password-reset"]

CRAWL_TIMEOUTS = {
    "Basic": 120,
    "Professional": 300,
}


def same_domain(base, target):
    return urlparse(base).netloc == urlparse(target).netloc


def fetch_robots_paths(base_url: str) -> list:
    """Parse robots.txt to find disallowed (often sensitive) paths."""
    paths = []
    try:
        r = requests.get(urljoin(base_url, "/robots.txt"), timeout=5)
        if r.status_code == 200:
            for line in r.text.splitlines():
                m = re.match(r'(?:Disallow|Allow):\s*(.+)', line, re.IGNORECASE)
                if m:
                    path = m.group(1).strip()
                    if path and path != '/':
                        paths.append(urljoin(base_url, path))
    except Exception:
        pass
    return paths


def fetch_sitemap_urls(base_url: str) -> list:
    """Parse sitemap.xml for URL discovery."""
    urls = []
    try:
        r = requests.get(urljoin(base_url, "/sitemap.xml"), timeout=5)
        if r.status_code == 200:
            urls = re.findall(r'<loc>([^<]+)</loc>', r.text)
    except Exception:
        pass
    return [u for u in urls if same_domain(base_url, u)]


def crawl_sync(start_url, tier="Basic", auth=None):
    """
    Multi-signal crawler with robots.txt, sitemap.xml, JS endpoint extraction,
    and high-value path probing.
    """
    if tier == "Professional":
        max_urls  = 300
        max_depth = 3
    else:
        max_urls  = 50
        max_depth = 1

    session = requests.Session()
    # Apply auth cookies/headers if provided
    if auth:
        for k, v in auth.get("cookies", {}).items():
            session.cookies.set(k, v)
        session.headers.update(auth.get("headers", {}))

    visited = set()
    queue   = [(start_url, 0)]
    results = set()
    js_parser = JSParser()

    # Seed with robots.txt and sitemap
    for path_url in fetch_robots_paths(start_url):
        queue.append((path_url, 0))
    for sitemap_url in fetch_sitemap_urls(start_url):
        queue.append((sitemap_url, 0))

    # Seed with high-value paths (always probe regardless of crawl depth)
    base = start_url.rstrip("/")
    for path in HIGH_VALUE_PATHS:
        results.add(base + path)

    while queue:
        url, depth = queue.pop(0)

        if url in visited or depth > max_depth or len(results) > max_urls:
            continue

        visited.add(url)

        try:
            res = session.get(url, timeout=8, allow_redirects=True)
            if res.status_code in (301, 302, 307, 308):
                loc = res.headers.get("Location", "")
                if loc and same_domain(start_url, urljoin(url, loc)):
                    queue.append((urljoin(url, loc), depth))
            results.add(url)

            soup = BeautifulSoup(res.text, "html.parser")

            # Extract anchor links
            for a in soup.find_all("a", href=True):
                full = urljoin(url, a["href"])
                if same_domain(start_url, full) and full not in visited:
                    queue.append((full, depth + 1))

            # Extract form action URLs
            for form in soup.find_all("form", action=True):
                full = urljoin(url, form["action"])
                if same_domain(start_url, full):
                    results.add(full)

            # Extract JS endpoints
            js_endpoints = js_parser.extract_endpoints(res.text, url)
            if tier == "Professional":
                results.update(js_endpoints)
            else:
                results.update(list(js_endpoints)[:10])

        except Exception:
            continue

    return list(results)


async def _crawl_async(url: str, tier: str, auth: dict = None) -> tuple:
    """Run the async Crawler with a hard timeout so the job never stalls."""
    max_pages = 300 if tier == "Professional" else 50
    timeout_s = CRAWL_TIMEOUTS.get(tier, 120)

    crawler = Crawler(base_url=url, max_pages=max_pages)

    async with httpx.AsyncClient(
        cookies=auth.get("cookies", {}) if auth else None,
        headers=auth.get("headers", {}) if auth else None,
        follow_redirects=True,
        timeout=20,
    ) as client:
        try:
            endpoints, forms = await asyncio.wait_for(
                crawler.crawl(client),
                timeout=timeout_s,
            )
        except asyncio.TimeoutError:
            logger.warning(f"[CRAWL] Timeout after {timeout_s}s — returning partial results")
            endpoints = list(crawler.endpoints)
            forms = crawler.forms

    return endpoints, forms



async def process(job):
    job_id = job.get("job_id")
    target = job.get("url")
    tier = job.get("tier", "Basic")
    auth = job.get("auth")

    try:
        logger.info(f"Starting crawl: {target}", job_id)

        push_log(job_id, f"[CRAWL] Starting {tier} crawl for {target}", tier=tier)

        # Use async crawler if available, fall back to sync
        try:
            found_urls, _ = await _crawl_async(target, tier, auth)  # Only capture endpoints

        except Exception:
            # Fall back to synchronous crawling
            found_urls = crawl_sync(target, tier, auth)
        
        filtered_urls = [
            u for u in found_urls
            if not any(blocked in u for blocked in BLOCKED_PATHS)
        ]

        log_event(job_id, "CRAWL", f"Found {len(filtered_urls)} URLs")
        push_log(job_id, f"[CRAWL] Discovery complete. Found {len(filtered_urls)} endpoints.", tier=tier)

        # ✅ ALWAYS pass dict (CRITICAL FIX)
        handle_completion(job_id, "crawl", {
            "urls": filtered_urls
        })

        # Also call the pipeline completion handler
        on_crawl_complete(job_id, filtered_urls, auth=auth, tier=tier)

    except Exception as e:
        logger.error(f"Crawl failed: {str(e)}", job_id)

        logger.error(f"[CRAWL] Fatal error: {e}", job_id)


async def worker():
    while True:
        job = None
        try:
            # Use the proper queue popping mechanism from base_worker
            from workers.base_worker import fetch as pop_queue
            job = pop_queue(CRAWL_QUEUE)
            
            if job:
                await process(job)
            else:
                await asyncio.sleep(1)
        except Exception as e:
            logger.error(f"[CRAWL] Worker error: {e}", job_id=job.get("job_id") if job else "N/A")
            await asyncio.sleep(1)


def handle(job):
    """Synchronous handler for worker_loop compatibility"""
    job_id = job["job_id"]
    url = job["url"]
    tier = job.get("tier", "Basic")
    auth = job.get("auth")

    push_log(job_id, f"[CRAWL] Starting {tier} crawl for {url}", tier=tier)

    try:
        # Try async first, fall back to sync
        try:
            loop = asyncio.get_event_loop()
            found_urls = loop.run_until_complete(_crawl_async(url, tier, auth))
        except (RuntimeError, Exception):
            # Fall back to synchronous crawling
            found_urls = crawl_sync(url, tier, auth)
    except Exception as e:
        logger.error(f"[CRAWL] Fatal error: {e}")
        found_urls = []

    filtered_urls = [
        u for u in found_urls
        if not any(blocked in u for blocked in BLOCKED_PATHS)
    ]

    push_log(job_id, f"[CRAWL] Filtered {len(found_urls)-len(filtered_urls)} paths.", tier=tier)
    push_log(job_id, f"[CRAWL] Discovery complete. Found {len(filtered_urls)} endpoints.", tier=tier)

    # ✅ ALWAYS pass dict (CRITICAL FIX)
    handle_completion(job_id, "crawl", {
        "urls": filtered_urls
    })

    # Also call the pipeline completion handler
    on_crawl_complete(job_id, filtered_urls, auth=auth, tier=tier)


if __name__ == "__main__":
    # Support both async worker and worker_loop modes
    try:
        asyncio.run(worker())
    except KeyboardInterrupt:
        logger.info("[CRAWL] Worker stopped by user")
    except Exception as e:
        logger.error(f"[CRAWL] Worker failed: {e}")
        # Fall back to worker_loop for compatibility
        worker_loop(CRAWL_QUEUE, handle)
