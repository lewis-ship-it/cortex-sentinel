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
# ──────────────────────────────────────────────────────────────────────────────

import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import asyncio
import httpx

from workers.base_worker import worker_loop, push_log
from task_queue.queues import CRAWL_QUEUE
from core.pipeline import on_crawl_complete
from scanner.js_parser import JSParser
from scanner.dast.crawler import Crawler

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


def crawl(start_url, tier="Basic", auth=None):
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
BLOCKED_PATHS = ["/register", "/signup", "/auth/sign-up", "/password-reset"]

def handle(job):
    job_id = job["job_id"]
    url    = job["url"]
    tier   = job.get("tier", "Basic")
    auth   = job.get("auth")

    push_log(job_id, f"[CRAWL] Starting {tier} crawl for {url}", tier=tier)

    # 1. Use the advanced Crawler class instead of the simple function
    # Note: Professional tier uses higher limits for better discovery
    max_p = 300 if tier == "Professional" else 50
    crawler = Crawler(base_url=url, max_pages=max_p)

    async def run_discovery():
        async with httpx.AsyncClient(
            cookies=auth.get("cookies", {}) if auth else None,
            headers=auth.get("headers", {}) if auth else None,
            follow_redirects=True
        ) as client:
            endpoints, forms = await crawler.crawl(client)
            return endpoints

    # Execute the async crawler
    found_urls = asyncio.run(run_discovery())

    # 2. Filter results
    filtered_urls = [
        u for u in found_urls 
        if not any(blocked in u for blocked in BLOCKED_PATHS)
    ]

    push_log(job_id, f"[CRAWL] Discovery complete. Found {len(filtered_urls)} endpoints.", tier=tier)

    # 3. Proceed to pipeline
    on_crawl_complete(job_id, filtered_urls, auth=auth, tier=tier)


if __name__ == "__main__":
    worker_loop(CRAWL_QUEUE, handle)