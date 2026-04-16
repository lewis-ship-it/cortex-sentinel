import os
import json
import asyncio
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()


class AIBrain:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-1.5-flash")

    # ── Validate Finding ────────────────────────────────────────────────────
    async def validate_finding(self, finding) -> dict:
        prompt = f"""
        You are a senior penetration tester.

        Analyze this finding:
        {json.dumps(finding, indent=2)}

        Answer STRICTLY in JSON:
        {{
          "valid": true/false,
          "confidence": 0.0-1.0,
          "reason": "short explanation",
          "severity": "Low/Medium/High/Critical"
        }}
        """
        try:
            res = await asyncio.to_thread(self.model.generate_content, prompt)
            text = res.text.strip()
            if "{" in text:
                text = text[text.find("{"):text.rfind("}") + 1]
            return json.loads(text)
        except Exception as e:
            return {
                "valid": True,
                "confidence": 0.5,
                "reason": f"AI error: {str(e)}",
                "severity": finding.get("severity", "Medium"),
            }

    # ── Generate Smart Payloads ─────────────────────────────────────────────
    async def generate_payloads(self, context) -> list:
        prompt = f"""
        You are an advanced exploit developer.

        Target context:
        {context}

        Generate 5 advanced payloads for SQL Injection OR XSS.

        Return JSON:
        {{
          "payloads": ["...", "..."]
        }}
        """
        try:
            res = await asyncio.to_thread(self.model.generate_content, prompt)
            text = res.text.strip()
            if "{" in text:
                text = text[text.find("{"):text.rfind("}") + 1]
            return json.loads(text).get("payloads", [])
        except Exception:
            return []

    # ── Analyze Attack Chain ────────────────────────────────────────────────
    async def analyze_attack_chain(self, findings) -> dict:
        prompt = f"""
        You are an elite penetration tester.

        These vulnerabilities were found:
        {json.dumps(findings, indent=2)}

        Identify REAL attack chains.

        Return JSON:
        {{
          "chains": [
            {{
              "steps": ["XSS", "Session Hijack", "Admin Access"],
              "impact": "Full account takeover",
              "severity": "Critical"
            }}
          ]
        }}
        """
        try:
            res = await asyncio.to_thread(self.model.generate_content, prompt)
            text = res.text.strip()
            if "{" in text:
                text = text[text.find("{"):text.rfind("}") + 1]
            return json.loads(text)
        except Exception:
            return {"chains": []}

    # ── Prioritize Targets ──────────────────────────────────────────────────
    async def prioritize_targets(self, endpoints) -> list:
        prompt = f"""
        You are a web security expert.

        Rank these endpoints by likelihood of vulnerability:
        {json.dumps(endpoints[:50], indent=2)}

        Return JSON:
        {{
          "priority": ["url1", "url2"]
        }}
        """
        try:
            res = await asyncio.to_thread(self.model.generate_content, prompt)
            text = res.text.strip()
            if "{" in text:
                text = text[text.find("{"):text.rfind("}") + 1]
            return json.loads(text).get("priority", endpoints)
        except Exception:
            return endpoints
