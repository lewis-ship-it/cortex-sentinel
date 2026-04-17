# workers/crawl_worker.py
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from workers.base_worker import worker_loop, push_log
from task_queue.queues import CRAWL_QUEUE
from core.pipeline import on_crawl_complete
from scanner.js_parser import JSParser

def same_domain(base, target):
    return urlparse(base).netloc == urlparse(target).netloc

def crawl(start_url, tier="Basic"):
    # TIERED LIMITS: Branched from your original constants
    if tier == "Professional":
        max_urls = 300
        max_depth = 3
    else:
        max_urls = 50 
        max_depth = 1 

    visited = set()
    queue = [(start_url, 0)]
    results = set()
    js_parser = JSParser()

    while queue:
        url, depth = queue.pop(0)

        if url in visited or depth > max_depth or len(results) > max_urls:
            continue

        visited.add(url)

        try:
            # Use a timeout to prevent hanging workers
            res = requests.get(url, timeout=5)
            results.add(url)

            soup = BeautifulSoup(res.text, "html.parser")

            # YOUR ORIGINAL LOGIC: Extract links
            for a in soup.find_all("a", href=True):
                full = urljoin(url, a["href"])
                if same_domain(start_url, full):
                    queue.append((full, depth + 1))

            # YOUR ORIGINAL LOGIC: Extract JS endpoints
            # Branched to limit processing for Basic
            js_endpoints = js_parser.extract_endpoints(res.text, url)
            if tier == "Professional":
                results.update(js_endpoints)
            else:
                results.update(list(js_endpoints)[:10]) # Limit discovery for Basic

        except Exception:
            continue

    return list(results)

def handle(job):
    job_id = job["job_id"]
    url = job["url"]
    tier = job.get("tier", "Basic")

    push_log(job_id, f"[CRAWL] Starting {tier} crawl for {url}", tier=tier)
    
    found_urls = crawl(url, tier=tier)
    
    push_log(job_id, f"[CRAWL] Found {len(found_urls)} URLs", tier=tier)
    on_crawl_complete(job_id, found_urls)

if __name__ == "__main__":
    worker_loop(CRAWL_QUEUE, handle)