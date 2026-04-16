import requests
import time
import logging

from workers.base_worker import worker_loop, push_log
from task_queue.queues import SCAN_QUEUE
from core.pipeline import on_scan_complete
from core.session_store import get_session
from scanner.fuzzer import SmartFuzzer
from scanner.detector import Detector
from scanner.context_engine import ContextEngine

logging.basicConfig(level=logging.DEBUG)

detector = Detector()
context_engine = ContextEngine()
fuzzer = SmartFuzzer()

TIMEOUT = 6


def scan_url(job_id, target_url):
    findings = []
    
    session = get_session(job_id) or {}
    cookies = session.get("cookies", {})
    headers = session.get("headers", {})
    
    # Common injectable parameters to test
    test_params = ["q", "search", "id", "user", "name", "email", "comment", "message", "text"]
    
    try:
        baseline = requests.get(target_url, cookies=cookies, headers=headers, timeout=TIMEOUT)
        baseline_text = baseline.text[:5000]
        
        payloads = fuzzer.generate(["<script>alert(1)</script>", "' OR 1=1 --", "1' AND '1'='1"])
        
        for param in test_params:
            for payload in payloads:
                injected = f"{target_url}?{param}={payload}"
                
                try:
                    start = time.time()
                    r = requests.get(injected, cookies=cookies, headers=headers, timeout=TIMEOUT)
                    delay = time.time() - start
                    body = r.text[:5000]
                    
                    # XSS Detection
                    if detector.detect_xss(body, payload):
                        findings.append({
                            "type": "XSS",
                            "target_url": injected,
                            "payload": payload,
                            "param": param,
                            "severity": "High",
                            "confidence": 0.85
                        })
                        push_log(job_id, f"[XSS] Found in {param}")
                    
                    # SQLi Detection - check for errors and time-based
                    sql_keywords = ["sql", "mysql", "syntax", "warning", "error", "exception"]
                    if any(keyword in body.lower() for keyword in sql_keywords):
                        findings.append({
                            "type": "SQL Injection",
                            "target_url": injected,
                            "payload": payload,
                            "param": param,
                            "severity": "Critical",
                            "confidence": 0.9
                        })
                        push_log(job_id, f"[SQLi] Found in {param}")
                    
                    # Reflection without encoding
                    if payload in body and payload not in baseline_text:
                        findings.append({
                            "type": "Reflection",
                            "target_url": injected,
                            "payload": payload,
                            "param": param,
                            "severity": "Medium",
                            "confidence": 0.6
                        })
                        push_log(job_id, f"[Reflection] Found in {param}")
                
                except requests.exceptions.Timeout:
                    push_log(job_id, f"[Timeout] {param}={payload}")
                except Exception as e:
                    logging.debug(f"[Error] Testing {param}: {e}")
    
    except Exception as e:
        push_log(job_id, f"[Error] Scan failed: {str(e)}")
        logging.error(f"Scan error: {e}")
    
    return findings


def handle(job):
    job_id = job["job_id"]
    target_url = job["target_url"]
    
    push_log(job_id, f"[SCAN] Starting scan for {target_url}")
    
    findings = scan_url(job_id, target_url)
    
    push_log(job_id, f"[SCAN] Completed - Found {len(findings)} vulnerabilities")
    
    on_scan_complete(job_id, findings)


if __name__ == "__main__":
    worker_loop(SCAN_QUEUE, handle)
