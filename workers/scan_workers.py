# workers/scan_workers.py

import asyncio
import logging
import httpx

from task_queue.redis_client import pop, push, retry
from task_queue.queues import SCAN_QUEUE, AGGREGATION_QUEUE
from scanner.payload_mutator import PayloadMutator
from scanner.priority_engine import PriorityEngine
from scanner.param_engine import ParamEngine
from scanner.rate_limiter import RateLimiter

mutator     = PayloadMutator()
planner     = PriorityEngine()
param_eng   = ParamEngine()
limiter     = RateLimiter()


async def _test_sqli_payload(client, url, payload):
    """Inject a SQLi payload into URL params and check for reflection / errors."""
    params = param_eng.extract_params(url)
    if not params:
        params = ["id", "q", "search"]

    for param in params:
        test_url = param_eng.inject_payload(url, param, payload)
        try:
            res = await client.get(test_url, timeout=10)
            errors = ["sql", "mysql", "syntax error", "warning", "sqlite"]
            if any(e in res.text.lower() for e in errors) or payload in res.text:
                return {
                    "type":      "SQL Injection",
                    "url":       test_url,
                    "parameter": param,
                    "payload":   payload,
                    "severity":  "Critical",
                    "confidence": 0.8,
                    "evidence":  payload
                }
        except Exception:
            continue
    return None


async def _test_xss_payload(client, url, payload):
    """Inject an XSS payload into URL params and check for reflection."""
    params = param_eng.extract_params(url)
    if not params:
        params = ["q", "search", "input"]

    for param in params:
        test_url = param_eng.inject_payload(url, param, payload)
        try:
            res = await client.get(test_url, timeout=10)
            if payload in res.text:
                return {
                    "type":      "Cross-Site Scripting (XSS)",
                    "url":       test_url,
                    "parameter": param,
                    "payload":   payload,
                    "severity":  "High",
                    "confidence": 0.75,
                    "evidence":  payload
                }
        except Exception:
            continue
    return None


async def smart_scan(url):
    findings = []
    attacks  = planner.choose_attacks(url)

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for attack in attacks:

            if attack == "sqli":
                for payload in mutator.mutate("' OR 1=1--"):
                    limiter.wait(url)
                    res = await _test_sqli_payload(client, url, payload)
                    if res:
                        findings.append(res)

            if attack == "xss":
                for payload in mutator.mutate("<script>alert(1)</script>"):
                    limiter.wait(url)
                    res = await _test_xss_payload(client, url, payload)
                    if res:
                        findings.append(res)

    return findings


async def main():
    while True:
        job = pop(SCAN_QUEUE)

        if not job:
            await asyncio.sleep(1)
            continue

        try:
            job_id = job["job_id"]
            url    = job["url"]

            logging.info(f"[SMART SCAN] {url}")

            findings = await smart_scan(url)

            push(AGGREGATION_QUEUE, {
                "job_id":   job_id,
                "findings": findings
            })

        except Exception as e:
            retry(SCAN_QUEUE, job, str(e))


asyncio.run(main())