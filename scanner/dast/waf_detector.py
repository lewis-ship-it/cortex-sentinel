# scanner/dast/waf_detector.py
#
# ENHANCED WAF DETECTOR — Comprehensive Web Application Firewall detection
# Uses multiple strategies: header analysis, response signatures, behavioral analysis,
# challenge-response testing, and timing analysis

import httpx
import re
import asyncio
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class WAFDetectionMethod(Enum):
    HEADER_ANALYSIS = "header_analysis"
    BODY_SIGNATURES = "body_signatures"
    BEHAVIORAL = "behavioral"
    CHALLENGE_RESPONSE = "challenge_response"
    TIMING_ANALYSIS = "timing_analysis"

@dataclass
class WAFSignature:
    name: str
    headers: List[str]
    body_patterns: List[str]
    cookies: List[str]
    status_codes: List[int]
    challenge_required: bool = False
    confidence_threshold: float = 0.7

class WAFDetector:
    def __init__(self, config: Optional[Dict] = None):
        self.config = {
            "timeout": 15,
            "max_concurrent_checks": 5,
            "min_confidence": 0.6,
            "enable_aggressive_tests": True,
            "retry_count": 2,
            "delay_between_requests": 0.5,
            **(config or {})
        }
        
        self.signatures = self._load_waf_signatures()
        self.detection_stats = {}

    def _load_waf_signatures(self) -> Dict[str, WAFSignature]:
        """Load comprehensive WAF signatures."""
        return {
            "Cloudflare": WAFSignature(
                name="Cloudflare",
                headers=[
                    "__cfduid", "cf-ray", "cloudflare-nginx", "cloudflare",
                    "cf-cache-status", "cf-connecting-ip", "cf-request-id",
                    "cf-worker", "cf-edge-cache"
                ],
                body_patterns=[
                    "cloudflare", "cf-ray", "attention required", "ray id",
                    "cloudflare security", "your IP has been flagged"
                ],
                cookies=["__cfduid", "cf_clearance", "__cf_bm"],
                status_codes=[403, 429, 503],
                challenge_required=True
            ),
            "Akamai": WAFSignature(
                name="Akamai",
                headers=[
                    "akamai-ch", "akamai-ghost", "true-client-ip",
                    "x-akamai-transformed", "x-akamai-staging",
                    "akamai-origin-hop", "x-akamai-config-log-id"
                ],
                body_patterns=[
                    "akamai", "access denied", "denied by akamai",
                    "akamai ghost", "akamai security"
                ],
                cookies=["akamai"],
                status_codes=[403, 500]
            ),
            "AWS WAF": WAFSignature(
                name="AWS WAF",
                headers=[
                    "x-amzn-requestid", "awselb", "x-amz-cf-id",
                    "x-amzn-remapped-status", "x-amzn-errortype",
                    "x-amz-apigw-id", "x-amzn-trace-id"
                ],
                body_patterns=[
                    "awselb", "request id", "request blocked",
                    "aws waf", "amazon", "aws security"
                ],
                cookies=[],
                status_codes=[403, 405, 500]
            ),
            "ModSecurity": WAFSignature(
                name="ModSecurity",
                headers=[
                    "mod_security", "modsecurity", "server: mod_security",
                    "mod_security-message", "mod_security-action"
                ],
                body_patterns=[
                    "mod_security", "modsecurity", "not acceptable",
                    "an error was encountered", "modsecurity action"
                ],
                cookies=[],
                status_codes=[403, 406, 500]
            ),
            "Imperva/Incapsula": WAFSignature(
                name="Imperva/Incapsula",
                headers=[
                    "x-iinfo", "x-cdn", "incap_ses", "visid_incap",
                    "x-cdn-forward", "x-incap-id"
                ],
                body_patterns=[
                    "incapsula", "imperva", "incident id", "access denied",
                    "imperva secure", "incapsula incident"
                ],
                cookies=["incap_ses_", "visid_incap_"],
                status_codes=[403, 409, 500],
                challenge_required=True
            ),
            "F5 BIG-IP ASM": WAFSignature(
                name="F5 BIG-IP ASM",
                headers=[
                    "big-ip", "f5", "x-wa-info", "x-ctx", "x-wa-event",
                    "f5_trace_id", "x-f5-forwarded-proto"
                ],
                body_patterns=[
                    "big-ip", "f5", "request rejected", "support id",
                    "bigip", "f5 security"
                ],
                cookies=["F5_HT_shrinked", "F5_ST"],
                status_codes=[403, 500]
            ),
            "Sucuri": WAFSignature(
                name="Sucuri",
                headers=[
                    "x-sucuri-id", "sucuri", "server: sucuri",
                    "x-sucuri-cache", "x-sucuri-block"
                ],
                body_patterns=[
                    "sucuri", "cloudproxy", "access denied",
                    "sucuri website firewall", "sucuri security"
                ],
                cookies=["sucuri_cloudproxy"],
                status_codes=[403, 500]
            ),
            "Wordfence": WAFSignature(
                name="Wordfence",
                headers=["wordfence", "x-wf-", "wf-"],
                body_patterns=[
                    "wordfence", "this request was blocked",
                    "generated by wordfence", "wordfence security"
                ],
                cookies=[],
                status_codes=[403, 500]
            ),
            "Fastly": WAFSignature(
                name="Fastly",
                headers=[
                    "fastly", "x-served-by", "x-cache", "x-cache-hits",
                    "fastly-debug", "fastly-ff", "x-fastly-request-id"
                ],
                body_patterns=["fastly", "request blocked", "fastly error"],
                cookies=[],
                status_codes=[403, 500]
            ),
            "Barracuda": WAFSignature(
                name="Barracuda",
                headers=["barracuda", "barra", "x-barracuda-"],
                body_patterns=["barracuda", "blocked by barracuda"],
                cookies=[],
                status_codes=[403, 500]
            ),
            "FortiWeb": WAFSignature(
                name="FortiWeb",
                headers=["fortiweb", "x-fortiweb-", "fortiguard"],
                body_patterns=["fortiweb", "fortinet", "security violation"],
                cookies=[],
                status_codes=[403, 500]
            ),
            "Generic": WAFSignature(
                name="Generic",
                headers=[
                    "waf", "firewall", "security", "blocked",
                    "x-security", "x-protected-by"
                ],
                body_patterns=[
                    "blocked", "forbidden", "security", "firewall",
                    "access denied", "not acceptable"
                ],
                cookies=[],
                status_codes=[403, 406, 429, 500, 503],
                confidence_threshold=0.4
            )
        }

    async def detect(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        """
        Comprehensive WAF detection using multiple strategies.
        
        Args:
            client: HTTP client
            url: Target URL
            
        Returns:
            Dictionary with detection results
        """
        detection_results = {
            "detected": False,
            "waf_name": "Unknown",
            "confidence": 0.0,
            "methods_used": [],
            "evidence": {},
            "details": {}
        }
        
        try:
            # Run all detection methods concurrently
            tasks = [
                self._detect_via_header_analysis(client, url),
                self._detect_via_body_signatures(client, url),
                self._detect_via_behavioral_analysis(client, url),
                self._detect_via_challenge_response(client, url),
                self._detect_via_timing_analysis(client, url)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            waf_scores = {}
            for result in results:
                if isinstance(result, dict) and result.get("detected"):
                    waf_name = result["waf_name"]
                    confidence = result["confidence"]
                    if waf_name not in waf_scores:
                        waf_scores[waf_name] = 0
                    waf_scores[waf_name] += confidence
                    
                    # Collect evidence
                    if waf_name not in detection_results["evidence"]:
                        detection_results["evidence"][waf_name] = []
                    detection_results["evidence"][waf_name].extend(result.get("evidence", []))
                    
                    detection_results["methods_used"].extend(result.get("methods", []))
            
            # Determine the most likely WAF
            if waf_scores:
                best_waf = max(waf_scores.items(), key=lambda x: x[1])
                if best_waf[1] >= self.config["min_confidence"]:
                    detection_results.update({
                        "detected": True,
                        "waf_name": best_waf[0],
                        "confidence": min(best_waf[1], 1.0),
                        "details": {
                            "all_scores": waf_scores,
                            "primary_methods": list(set(detection_results["methods_used"]))
                        }
                    })
            
        except Exception as e:
            logger.error(f"WAF detection failed for {url}: {e}")
            detection_results["error"] = str(e)
        
        return detection_results

    async def _detect_via_header_analysis(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        """Detect WAF via response header analysis."""
        try:
            response = await client.get(url, timeout=self.config["timeout"])
            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
            headers_str = str(headers_lower).lower()
            
            results = []
            for waf_name, signature in self.signatures.items():
                score = 0.0
                evidence = []
                
                # Check headers
                for header_pattern in signature.headers:
                    header_lower = header_pattern.lower()
                    if any(header_lower in k for k in headers_lower.keys()):
                        score += 0.3
                        evidence.append(f"Header pattern: {header_pattern}")
                
                if score >= signature.confidence_threshold:
                    results.append({
                        "waf_name": waf_name,
                        "confidence": min(score, 1.0),
                        "evidence": evidence,
                        "methods": [WAFDetectionMethod.HEADER_ANALYSIS.value]
                    })
            
            if results:
                # Return the highest confidence result
                return max(results, key=lambda x: x["confidence"])
                
        except Exception as e:
            logger.debug(f"Header analysis failed: {e}")
        
        return {"detected": False}

    async def _detect_via_body_signatures(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        """Detect WAF via response body signatures."""
        try:
            response = await client.get(url, timeout=self.config["timeout"])
            body_lower = response.text[:5000].lower()  # First 5KB only
            
            results = []
            for waf_name, signature in self.signatures.items():
                score = 0.0
                evidence = []
                
                # Check body patterns
                for pattern in signature.body_patterns:
                    pattern_lower = pattern.lower()
                    if pattern_lower in body_lower:
                        score += 0.2
                        evidence.append(f"Body pattern: {pattern}")
                
                if score >= signature.confidence_threshold:
                    results.append({
                        "waf_name": waf_name,
                        "confidence": min(score, 1.0),
                        "evidence": evidence,
                        "methods": [WAFDetectionMethod.BODY_SIGNATURES.value]
                    })
            
            if results:
                return max(results, key=lambda x: x["confidence"])
                
        except Exception as e:
            logger.debug(f"Body signature analysis failed: {e}")
        
        return {"detected": False}

    async def _detect_via_behavioral_analysis(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        """Detect WAF via behavioral analysis (attack payload responses)."""
        attack_payloads = [
            ("?id=1' OR 1=1--", "SQLi"),
            ("?q=<script>alert(1)</script>", "XSS"),
            ("?file=../../../../etc/passwd", "LFI"),
            ("?cmd=; id", "CMDI"),
            ("/?../etc/passwd", "Path Traversal"),
        ]
        
        try:
            results = []
            for payload, payload_type in attack_payloads:
                test_url = f"{url}{payload}"
                try:
                    response = await client.get(test_url, timeout=self.config["timeout"])
                    
                    # Check for WAF blocking patterns
                    if response.status_code in [403, 406, 429, 500, 503]:
                        body_lower = response.text[:2000].lower()
                        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                        
                        for waf_name, signature in self.signatures.items():
                            if response.status_code in signature.status_codes:
                                score = 0.0
                                evidence = []
                                
                                # Check for WAF-specific patterns
                                for pattern in signature.body_patterns:
                                    if pattern.lower() in body_lower:
                                        score += 0.15
                                        evidence.append(f"Blocked {payload_type} - Body: {pattern}")
                                
                                for header_pattern in signature.headers:
                                    if any(header_pattern.lower() in k for k in headers_lower.keys()):
                                        score += 0.25
                                        evidence.append(f"Blocked {payload_type} - Header: {header_pattern}")
                                
                                if score >= signature.confidence_threshold:
                                    results.append({
                                        "waf_name": waf_name,
                                        "confidence": min(score, 1.0),
                                        "evidence": evidence,
                                        "methods": [WAFDetectionMethod.BEHAVIORAL.value]
                                    })
                                
                                await asyncio.sleep(self.config["delay_between_requests"])
                                
                except Exception as e:
                    logger.debug(f"Behavioral test failed for {payload}: {e}")
                    continue
            
            if results:
                # Group by WAF and sum confidence
                waf_scores = {}
                for result in results:
                    waf_name = result["waf_name"]
                    if waf_name not in waf_scores:
                        waf_scores[waf_name] = 0
                    waf_scores[waf_name] += result["confidence"]
                
                best_waf = max(waf_scores.items(), key=lambda x: x[1])
                return {
                    "waf_name": best_waf[0],
                    "confidence": min(best_waf[1], 1.0),
                    "evidence": [f"Behavioral detection with {best_waf[1]:.1f} confidence"],
                    "methods": [WAFDetectionMethod.BEHAVIORAL.value]
                }
                
        except Exception as e:
            logger.debug(f"Behavioral analysis failed: {e}")
        
        return {"detected": False}

    async def _detect_via_challenge_response(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        """Detect WAF via challenge-response tests."""
        # Tests for WAFs that present challenges (e.g., Cloudflare, Imperva)
        challenge_tests = [
            ("/", "GET"),
            ("/../", "GET"),
            ("/wp-admin/", "GET"),
            ("/", "POST")  # Empty POST to trigger challenges
        ]
        
        try:
            for path, method in challenge_tests:
                test_url = f"{url}{path}"
                try:
                    if method == "POST":
                        response = await client.post(test_url, data={}, timeout=self.config["timeout"])
                    else:
                        response = await client.get(test_url, timeout=self.config["timeout"])
                    
                    # Check for challenge patterns
                    body_lower = response.text.lower()
                    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                    
                    # Cloudflare challenge detection
                    if ("challenge" in body_lower and "cloudflare" in body_lower) or \
                       ("cf-chl-bypass" in headers_lower):
                        return {
                            "detected": True,
                            "waf_name": "Cloudflare",
                            "confidence": 0.9,
                            "evidence": ["Challenge-response test passed"],
                            "methods": [WAFDetectionMethod.CHALLENGE_RESPONSE.value]
                        }
                    
                    # Imperva challenge detection
                    if ("incapsula" in body_lower and "challenge" in body_lower) or \
                       ("incap_challenge" in headers_lower):
                        return {
                            "detected": True,
                            "waf_name": "Imperva/Incapsula",
                            "confidence": 0.85,
                            "evidence": ["Challenge-response test passed"],
                            "methods": [WAFDetectionMethod.CHALLENGE_RESPONSE.value]
                        }
                    
                    await asyncio.sleep(self.config["delay_between_requests"])
                    
                except Exception as e:
                    logger.debug(f"Challenge test failed: {e}")
                    continue
                    
        except Exception as e:
            logger.debug(f"Challenge-response analysis failed: {e}")
        
        return {"detected": False}

    async def _detect_via_timing_analysis(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        """Detect WAF via response timing analysis."""
        try:
            # Baseline timing
            start_time = time.time()
            await client.get(url, timeout=self.config["timeout"])
            baseline_time = time.time() - start_time
            
            # Timing with attack payload
            attack_url = f"{url}?id=1' OR 1=1--"
            start_time = time.time()
            await client.get(attack_url, timeout=self.config["timeout"])
            attack_time = time.time() - start_time
            
            # If attack response is significantly slower, might indicate WAF processing
            if attack_time > baseline_time * 3:  # 3x slower
                return {
                    "detected": True,
                    "waf_name": "Generic",
                    "confidence": 0.6,
                    "evidence": [f"Timing anomaly: {baseline_time:.3f}s vs {attack_time:.3f}s"],
                    "methods": [WAFDetectionMethod.TIMING_ANALYSIS.value]
                }
                
        except Exception as e:
            logger.debug(f"Timing analysis failed: {e}")
        
        return {"detected": False}

    async def get_detection_stats(self) -> Dict[str, Any]:
        """Get WAF detection statistics."""
        return self.detection_stats

# Legacy compatibility
async def detect_waf(client: httpx.AsyncClient, url: str) -> str:
    """Legacy function for backward compatibility."""
    detector = WAFDetector()
    result = await detector.detect(client, url)
    return result["waf_name"] if result["detected"] else "Unknown"
