import google.generativeai as genai
import os
import json
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

class AIBrain:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.error("CRITICAL: GEMINI_API_KEY is missing from environment.")
        
        genai.configure(api_key=api_key)
        
        # Using System Instructions to force the model into a 'Security Auditor' persona
        self.model = genai.GenerativeModel(
            model_name='gemini-1.5-flash',
            generation_config={"response_mime_type": "application/json"}, # Force JSON output
            system_instruction=(
                "You are an elite automated penetration testing engine. "
                "You only respond in structured JSON. You prioritize precision over verbosity. "
                "You never ignore potential evidence of data leakage or execution."
            )
        )

    def _clean_json(self, text: str) -> dict:
        """Removes markdown fluff and attempts to parse JSON safely."""
        try:
            # Handle cases where the model still adds ```json blocks
            text = text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except Exception as e:
            logger.error(f"AI JSON Parse Error: {e} | Raw Text: {text}")
            return {"error": "Invalid AI response format", "valid": False, "confidence": 0.0}

    async def analyze_attack_surface(self, crawl_data):
        """
        Takes raw crawl data and tells the scanner WHERE to hit hard.
        """
        prompt = f"""
        Analyze these endpoints: {json.dumps(crawl_data)}
        
        Identify the 3 most likely endpoints for:
        1. SQL Injection (check params like id, search, filter)
        2. SSRF (check params like url, file, path)
        3. Broken Access Control (check UUIDs or incremental IDs)

        Return a JSON list: [{{"url": "...", "reason": "...", "suggested_attack": "..."}}]
        """
        try:
            response = await self.model.generate_content_async(prompt)
            return self._clean_json(response.text)
        except Exception as e:
            return [{"error": f"AI Brain offline: {str(e)}"}]

    async def validate_finding(self, finding: dict, original_res: str = "", attack_res: str = ""):
        """
        The Final Sieve: Distinguishes between a real bug and a generic error page.
        """
        # Truncate bodies to save tokens and stay within context limits
        orig_body = original_res[:1000]
        attack_body = attack_res[:2000]

        prompt = f"""
        Analyze this DAST finding.
        FINDING: {json.dumps(finding)}
        
        Compare the baseline response with the attack response:
       BASELINE: {orig_body}
        ATTACK: {attack_body}
        FINDING: {json.dumps(finding)}

        DETERMINE:
        1. Is the change in the attack response statistically significant?
        2. Is the evidence (e.g. SQL error, XSS alert, delay) clearly present?
        3. Is this likely a custom error page (False Positive)?

        Return JSON: {{"valid": bool, "confidence": float, "reason": "string", "severity_adjustment": "string"}}
        """
        try:
            response = await self.model.generate_content_async(prompt)
            return self._clean_json(response.text)
        except Exception as e:
            logger.error(f"Validation failed: {e}")
            return {"valid": True, "confidence": 0.5, "reason": "Error during AI validation."}

    async def generate_exploit_poc(self, finding: dict):
        """
        Generates a custom Proof of Concept (PoC) for the final report.
        """
        prompt = f"""
        Generate a 'curl' command to reproduce this vulnerability:
        TYPE: {finding.get('type')}
        URL: {finding.get('url')}
        PAYLOAD: {finding.get('payload')}
        
        Include any necessary headers or data flags. 
        Return JSON: {{"poc_command": "...", "explanation": "..."}}
        """
        try:
            response = await self.model.generate_content_async(prompt)
            return self._clean_json(response.text)
        except Exception as e:
            return {"poc_command": "Manual verification required", "explanation": str(e)}