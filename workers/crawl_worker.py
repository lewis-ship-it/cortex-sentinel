# workers/crawl_worker.py

import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from workers.base_worker import worker_loop, push_log
from task_queue.queues import CRAWL_QUEUE
from core.pipeline import on_crawl_complete
from scanner.js_parser import JSParser

MAX_URLS = 300
MAX_DEPTH = 3


def same_domain(base, target):
    return urlparse(base).netloc == urlparse(target).netloc


def crawl(start_url):
    visited = set()
    queue = [(start_url, 0)]
    results = set()
    js_parser = JSParser()

    while queue:
        url, depth = queue.pop(0)

        if url in visited or depth > MAX_DEPTH or len(results) > MAX_URLS:
            continue

        visited.add(url)

        try:
            res = requests.get(url, timeout=5)
            results.add(url)

            soup = BeautifulSoup(res.text, "html.parser")

            # extract links
            for a in soup.find_all("a", href=True):
                full = urljoin(url, a["href"])
                if same_domain(start_url, full):
                    queue.append((full, depth + 1))

            # extract JS endpoints
            js_endpoints = js_parser.extract_endpoints(res.text, url)
            results.update(js_endpoints)

        except Exception:
            continue

    return list(results)


def handle(job):
    job_id = job["job_id"]
    url = job["url"]

    push_log(job_id, "[CRAWL] Started")

    urls = crawl(url)

    push_log(job_id, f"[CRAWL] Found {len(urls)} URLs")

    on_crawl_complete(job_id, urls)


if __name__ == "__main__":
    worker_loop(CRAWL_QUEUE, handle)