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

    # -------------------------
    # VALIDATE FINDING
    # -------------------------
    async def validate_finding(self, finding):
        """
        AI decides:
        - Is this real?
        - How dangerous is it?
        """

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
                "severity": finding.get("severity", "Medium")
            }

    # -------------------------
    # GENERATE SMART PAYLOADS
    # -------------------------
    async def generate_payloads(self, context):
        """
        AI creates new payloads based on target behavior
        """

        prompt = f"""
        You are an advanced exploit developer.

        Target context:
        {context}

        Generate 5 advanced payloads for:
        - SQL Injection OR
        - XSS

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

            data = json.loads(text)
            return data.get("payloads", [])

        except:
            return []

    # -------------------------
    # ANALYZE ATTACK CHAIN
    # -------------------------
    async def analyze_attack_chain(self, findings):
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

        except:
            return {"chains": []}

    # -------------------------
    # DECIDE NEXT TARGETS
    # -------------------------
    async def prioritize_targets(self, endpoints):
        """
        AI chooses high-risk endpoints
        """

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

            data = json.loads(text)
            return data.get("priority", endpoints)

        except:
            return endpoints
