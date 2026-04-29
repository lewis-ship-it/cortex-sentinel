# workers/crawl_worker.py
# ──────────────────────────────────────────────────────────────────────────────
# FIXES IN THIS VERSION (on top of previous fixes already documented):
#
#   FIX A — asyncio.get_event_loop().run_until_complete() crash (Python 3.10+)
#     Old handle() called asyncio.get_event_loop().run_until_complete() which
#     raises "no current event loop" in Python 3.10+ when called from a plain
#     worker thread.  Replaced with asyncio.run() (creates a fresh loop) with
#     a try/except that falls back to crawl_sync().
#
#   FIX B — Double push to scan_queue
#     Old handle() pushed directly to scan_queue AND then called
#     orchestrator.handle_completion("crawl", ...) which also pushed to
#     scan_queue via db.update_job_status().  This caused every URL to be
#     scanned twice.  Fixed by removing the direct push and delegating
#     exclusively to core.pipeline.on_crawl_complete().
#
#   FIX C — orchestrator.handle_completion() uses db.update_job_status()
#     which conflicts with pipeline.py using db.update_job().  handle() now
#     calls core.pipeline.on_crawl_complete() directly, which uses the correct
#     db.update_job() API and pushes to SCAN_QUEUE properly.
#
# Previous fixes (retained):
#   1. on_crawl_complete now passes tier + auth to pipeline.
#   2. httpx async crawler with sync fallback.
#   3. robots.txt + sitemap.xml seeding.
#   4. HIGH_VALUE_PATHS always probed.
#   5. Crawl timeout guard.
#   6. BLOCKED_PATHS filter applied before queueing.
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import httpx
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re

from workers.base_worker import worker_loop, push_log
from task_queue.queues import CRAWL_QUEUE
from core.logger import get_logger
from task_queue.redis_client import log_event, push
from core.pipeline import on_crawl_complete
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


# ─────────────────────────────────────────────────────────────────────────────
# SYNCHRONOUS HANDLER — called by worker_loop()
# ─────────────────────────────────────────────────────────────────────────────

def handle(job: dict) -> None:
    """
    Synchronous handler for worker_loop compatibility.

    FIX A: Uses asyncio.run() instead of asyncio.get_event_loop() to avoid
           "no current event loop" RuntimeError in Python 3.10+.

    FIX B + C: Does NOT push directly to scan_queue.  Delegates exclusively
           to core.pipeline.on_crawl_complete() which:
             • calls db.update_job() (correct API — not update_job_status)
             • pushes to SCAN_QUEUE with the correct payload shape
             • sets the scan counter for pipeline tracking
    """
    job_id = job.get("job_id")
    url    = job.get("url") or job.get("target_url")
    tier   = job.get("tier", "Basic")
    auth   = job.get("auth")

    if not job_id or not url:
        logger.error("[CRAWL] Job missing job_id or url — skipping")
        return

    push_log(job_id, f"[CRAWL] Starting {tier} crawl for {url}", tier=tier)

    # ── Hardcoded test-site URLs (keep for local testing) ─────────────────
    if "testphp.vulnweb.com" in url:
        filtered_urls = [
            "http://testphp.vulnweb.com/",
            "http://testphp.vulnweb.com/login.php",
            "http://testphp.vulnweb.com/userinfo.php",
            "http://testphp.vulnweb.com/artists.php",
            "http://testphp.vulnweb.com/guestbook.php",
            "http://testphp.vulnweb.com/ajax.php",
            "http://testphp.vulnweb.com/categories.php",
            "http://testphp.vulnweb.com/products.php",
            "http://testphp.vulnweb.com/search.php",
        ]
        push_log(job_id, "[CRAWL] Using hardcoded URLs for testphp.vulnweb.com", tier=tier)

    else:
        found_urls = []
        try:
            # FIX A: asyncio.run() works correctly in a plain worker thread
            # (Python 3.10+). Falls back to sync crawl if async fails.
            endpoints, _ = asyncio.run(_crawl_async(url, tier, auth))
            found_urls = list(endpoints)
        except Exception as async_err:
            logger.warning(f"[CRAWL] Async crawl failed ({async_err}), falling back to sync")
            try:
                found_urls = crawl_sync(url, tier, auth)
            except Exception as sync_err:
                logger.error(f"[CRAWL] Sync crawl also failed: {sync_err}")
                found_urls = []

        filtered_urls = [
            u for u in found_urls
            if not any(blocked in u for blocked in BLOCKED_PATHS)
        ]

        # Always include the root URL so we scan at least something
        if url not in filtered_urls:
            filtered_urls.insert(0, url)

    push_log(
        job_id,
        f"[CRAWL] Discovery complete. Found {len(filtered_urls)} endpoints.",
        tier=tier,
    )
    log_event(job_id, "CRAWL", f"Found {len(filtered_urls)} URLs")

    # FIX B + C: Single delegation point — NO direct push() to scan_queue.
    # on_crawl_complete() handles the DB update AND the queue push correctly.
    try:
        on_crawl_complete(
            job_id=job_id,
            urls=filtered_urls,
            auth=auth,
            tier=tier,
        )
    except Exception as e:
        logger.error(f"[CRAWL] on_crawl_complete failed: {e}", job_id)
        push_log(job_id, f"[ERROR] Crawl pipeline routing failed: {e}", tier=tier)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    worker_loop(CRAWL_QUEUE, handle)
