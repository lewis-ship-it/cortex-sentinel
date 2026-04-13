# scanner/ai_brain.py
#
# PLACEMENT: Replace scanner/ai_brain.py entirely.
#
# WHAT CHANGED:
#   • Added detect_technology() — identifies CMS/framework from homepage HTML
#     so active_scanner can load targeted payload sets
#   • validate_finding() unchanged — still the main AI quality gate
#   • generate_payloads() kept but marked as unused in hot path
#     (static payloads in payloads.py are faster and more reliable)
#   • analyze_attack_chain() and prioritize_targets() unchanged

import os
import json
import asyncio
import logging
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


def _safe_parse(text: str) -> dict | None:
    try:
        s = text.find("{")
        e = text.rfind("}")
        if s >= 0 and e >= 0:
            return json.loads(text[s:e+1])
    except Exception:
        pass
    return None


class AIBrain:

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.warning("[AIBrain] GEMINI_API_KEY not set — AI features disabled")
        genai.configure(api_key=api_key or "")
        self.model   = genai.GenerativeModel("gemini-1.5-flash")
        self.enabled = bool(api_key)

    async def _call(self, prompt: str) -> str | None:
        if not self.enabled:
            return None
        try:
            res = await asyncio.to_thread(self.model.generate_content, prompt)
            return res.text.strip()
        except Exception as e:
            logger.warning(f"[AIBrain] API call failed: {e}")
            return None

    # ── Validate Finding ────────────────────────────────────────────────────
    async def validate_finding(self, finding: dict) -> dict:
        """
        Given a raw scanner finding, ask the AI whether it is a real
        vulnerability or a false positive, and what the true severity is.
        Used in filter_false_positives() in active_scanner.py.
        """
        prompt = f"""
You are a senior web application penetration tester.

Analyse this scanner finding and determine if it is a real vulnerability
or a false positive. Consider the evidence carefully.

FINDING:
{json.dumps(finding, indent=2)}

Answer STRICTLY in JSON — no markdown, no explanation outside the JSON:
{{
  "valid": true or false,
  "confidence": 0.0 to 1.0,
  "reason": "one sentence explanation",
  "severity": "Low" or "Medium" or "High" or "Critical"
}}
"""
        text = await self._call(prompt)
        if not text:
            return {"valid": True, "confidence": 0.5, "reason": "AI unavailable",
                    "severity": finding.get("severity", "Medium")}
        parsed = _safe_parse(text)
        return parsed if parsed else {
            "valid": True, "confidence": 0.5,
            "reason": "parse error", "severity": finding.get("severity", "Medium"),
        }

    # ── Detect Technology  (NEW) ────────────────────────────────────────────
    async def detect_technology(self, homepage_html: str, headers: dict) -> dict:
        """
        Analyse the homepage HTML + response headers to identify the tech stack.
        Returns a dict that active_scanner can use to load targeted payloads.

        Example return value:
        {
            "cms":       "WordPress",
            "framework": "PHP",
            "server":    "Apache",
            "database":  "MySQL",
            "notes":     "wp-content paths visible, X-Powered-By: PHP/8.1"
        }

        Call this at the start of scan() and pass result to payload selection.
        """
        prompt = f"""
You are a web technology fingerprinting expert.

Analyse the following HTTP response data and identify the technology stack.

RESPONSE HEADERS:
{json.dumps(headers, indent=2)}

HTML SNIPPET (first 3000 chars):
{homepage_html[:3000]}

Return ONLY valid JSON — no markdown:
{{
  "cms":       "WordPress | Drupal | Joomla | Laravel | Django | Rails | Spring | Next.js | Unknown",
  "framework": "PHP | Python | Ruby | Java | Node.js | .NET | Unknown",
  "server":    "Apache | Nginx | IIS | Caddy | Unknown",
  "database":  "MySQL | PostgreSQL | MSSQL | Oracle | MongoDB | Unknown",
  "notes":     "any additional clues (version numbers, specific paths, etc.)"
}}
"""
        text = await self._call(prompt)
        if not text:
            return {"cms": "Unknown", "framework": "Unknown",
                    "server": "Unknown", "database": "Unknown", "notes": ""}
        parsed = _safe_parse(text)
        return parsed if parsed else {
            "cms": "Unknown", "framework": "Unknown",
            "server": "Unknown", "database": "Unknown", "notes": str(text)[:200],
        }

    # ── Analyze Attack Chain ────────────────────────────────────────────────
    async def analyze_attack_chain(self, findings: list) -> dict:
        prompt = f"""
You are an elite penetration tester. These vulnerabilities were confirmed on a target:

{json.dumps(findings, indent=2)}

Identify realistic multi-step attack chains. Describe how an attacker
would chain these findings to achieve maximum impact.

Return ONLY valid JSON:
{{
  "chains": [
    {{
      "steps":  ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
      "impact": "Full account takeover / Data exfiltration / RCE / etc.",
      "severity": "Critical | High | Medium"
    }}
  ],
  "worst_case": "One sentence describing the worst realistic outcome"
}}
"""
        text = await self._call(prompt)
        if not text:
            return {"chains": [], "worst_case": ""}
        parsed = _safe_parse(text)
        return parsed if parsed else {"chains": [], "worst_case": ""}

    # ── Prioritize Targets ──────────────────────────────────────────────────
    async def prioritize_targets(self, endpoints: list) -> list:
        if not endpoints:
            return endpoints
        prompt = f"""
You are a web security expert. Rank these endpoints by their likelihood
of containing vulnerabilities (highest risk first).

Consider: auth paths, file params, admin panels, search, IDs in paths.

ENDPOINTS:
{json.dumps(endpoints[:60], indent=2)}

Return ONLY valid JSON:
{{"priority": ["url1", "url2", "...all urls ranked..."]}}
"""
        text = await self._call(prompt)
        if not text:
            return endpoints
        parsed = _safe_parse(text)
        return parsed.get("priority", endpoints) if parsed else endpoints

    # ── Generate Payloads (REFERENCE ONLY — not in hot path) ───────────────
    async def generate_payloads(self, context: dict) -> list:
        """
        NOT called during scanning — static payloads.py is faster and better.
        Kept here for experimental use or one-off targeted tests.
        """
        prompt = f"""
Target context: {json.dumps(context)}
Generate 5 advanced, WAF-bypassing payloads for the vulnerability type indicated.
Return ONLY JSON: {{"payloads": ["...", "..."]}}
"""
        text = await self._call(prompt)
        if not text:
            return []
        parsed = _safe_parse(text)
        return parsed.get("payloads", []) if parsed else []
