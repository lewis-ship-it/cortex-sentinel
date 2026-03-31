import os
import json
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

class AIReportGenerator:
    def __init__(self):
        # Setup Gemini
        api_key = os.getenv("GEMINI_API_KEY")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')

    async def generate_report(self, vulnerabilities, target):
        """Uses Gemini to perform high-level security reasoning."""
        if not vulnerabilities:
            return {"summary": "No vulnerabilities found.", "findings": []}

        # Create a structured prompt for the AI
        # We send the vulnerabilities as a list to save on API calls (one big push)
        vuln_data = json.dumps(vulnerabilities, indent=2)
        
        prompt = f"""
        You are a Senior Security Auditor. Analyze these vulnerabilities found on {target}.
        
        DATA:
        {vuln_data}

        TASK:
        For each vulnerability, provide:
        1. 'impact': A one-sentence business risk.
        2. 'exploitation': A step-by-step technical flow of how an attacker would use this.
        3. 'remediation': Precise code-level advice to fix it.
        4. 'confidence': A score from 0.1 to 1.0.

        Return the result as a VALID JSON object with the key 'findings' containing the list of analyzed results.
        """

        try:
            # Gemini call (Flash is incredibly fast)
            response = self.model.generate_content(prompt)
            
            # Clean the response to ensure it's pure JSON
            raw_text = response.text.replace('```json', '').replace('```', '').strip()
            ai_data = json.loads(raw_text)

            report = {
                "target": target,
                "summary": {
                    "total": len(vulnerabilities),
                    "critical": len([v for v in vulnerabilities if v.get('severity') == 'Critical']),
                    "high": len([v for v in vulnerabilities if v.get('severity') == 'High'])
                },
                "findings": ai_data.get("findings", [])
            }
            return report

        except Exception as e:
            print(f"[!] Gemini Error: {e}")
            # Return basic data if AI fails
            return {"target": target, "error": "AI analysis unavailable", "raw_findings": vulnerabilities}