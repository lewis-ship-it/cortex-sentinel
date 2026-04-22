# intelligence/ai_brain.py
# ──────────────────────────────────────────────────────────────────────────────
# INTELLIGENCE AI BRAIN — Ollama/qwen2.5-coder only. No external provider.
# google.generativeai has been permanently removed.
# Delegates to scanner.ai_brain for the actual Ollama transport layer.
# ──────────────────────────────────────────────────────────────────────────────

import json
import logging
from scanner.ai_brain import _call_ollama, _extract_json

logger = logging.getLogger(__name__)


class AIBrain:
    """
    Intelligence-layer AI Brain. Uses local Ollama exclusively.
    Raises on connectivity failure — no silent external fallback.
    """

    async def analyze_attack_surface(self, crawl_data: list) -> list:
        """
        Takes raw crawl data and identifies highest-priority attack surface.
        """
        prompt = f"""
Analyze these endpoints: {json.dumps(crawl_data[:50])}

Identify the 3 most likely endpoints for:
1. SQL Injection (check params like id, search, filter)
2. SSRF (check params like url, file, path)
3. Broken Access Control (check UUIDs or incremental IDs)

Return ONLY a JSON array:
[{{"url": "...", "reason": "...", "suggested_attack": "..."}}]
"""
        text = await _call_ollama(prompt)
        result = _extract_json(text)
        return result if isinstance(result, list) else []

    async def validate_finding(self, finding: dict,
                               original_res: str = "",
                               attack_res: str = "") -> dict:
        """
        Validates a DAST finding against baseline and attack responses.
        """
        prompt = f"""
Analyze this DAST finding:
FINDING: {json.dumps(finding)}

BASELINE RESPONSE (first 1000 chars):
{original_res[:1000]}

ATTACK RESPONSE (first 2000 chars):
{attack_res[:2000]}

DETERMINE:
1. Is the change in the attack response statistically significant?
2. Is the evidence (SQL error, XSS alert, delay) clearly present?
3. Is this likely a custom error page (False Positive)?

Return ONLY JSON:
{{"valid": true, "confidence": 0.0, "reason": "string", "severity_adjustment": "none/upgrade/downgrade"}}
"""
        text = await _call_ollama(prompt)
        return _extract_json(text)

    async def generate_exploit_poc(self, finding: dict) -> dict:
        """
        Generates a safe proof-of-concept curl command for a finding.
        """
        prompt = f"""
Generate a safe curl command to demonstrate this vulnerability (non-destructive only):
TYPE: {finding.get('type')}
URL: {finding.get('url') or finding.get('target_url')}
PAYLOAD: {finding.get('payload')}

Return ONLY JSON:
{{"poc_command": "curl ...", "explanation": "..."}}
"""
        text = await _call_ollama(prompt)
        return _extract_json(text)