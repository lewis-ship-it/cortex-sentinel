import os
import json
import asyncio
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

class ExploitGenerator:
    def __init__(self, model):
        self.model = model

    async def generate_poc(self, vuln_type, url, evidence=None):
        """
        Generates a functional, technical Proof of Concept (PoC) for a verified finding.
        """
        prompt = f"""
        Target: {url}
        Vulnerability: {vuln_type}
        Context/Evidence: {evidence}

        Task:
        1. Provide a specific, contextual payload (e.g., encoded if needed).
        2. Provide a 'curl' command to demonstrate the vulnerability.
        3. Explain why this specific payload is likely to bypass basic filters.

        Return ONLY a JSON object with keys: 'payload', 'curl_command', 'explanation'.
        Do not include markdown code blocks.
        """
        try:
            # We use to_thread because the generativeai library is synchronous
            response = await asyncio.to_thread(self.model.generate_content, prompt)
            raw_text = response.text.strip()
            # Basic cleanup if AI returns markdown
            if "{" in raw_text:
                raw_text = raw_text[raw_text.find("{"):raw_text.rfind("}") + 1]
            return json.loads(raw_text)
        except Exception as e:
            return {"error": f"PoC generation failed: {str(e)}"}

class AIReportGenerator:
    def __init__(self):
        # Setup Gemini
        api_key = os.getenv("GEMINI_API_KEY")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        self.exploit_gen = ExploitGenerator(self.model)

    async def generate_report(self, vulnerabilities, target):
        """
        Uses Gemini to perform security reasoning and automated exploit generation.
        """
        if not vulnerabilities:
            return {"summary": "No vulnerabilities found.", "findings": []}

        vuln_data = json.dumps(vulnerabilities, indent=2)
        
        # Phase 1: Reasoning and Filtering
        prompt = f"""
        You are a Senior Security Auditor. Analyze these findings for {target}.
        
        INSTRUCTIONS:
        - Identify REAL threats vs False Positives (e.g. test keys, generic samples).
        - For REAL threats, provide 'impact', 'exploitation' (general steps), and 'remediation'.
        - Assign a 'confidence' score (0.1 to 1.0).

        DATA:
        {vuln_data}

        Return a VALID JSON object with the key 'findings'. No markdown formatting.
        """

        try:
            # Step 1: Initial AI Analysis
            response = await asyncio.to_thread(self.model.generate_content, prompt)
            raw_text = response.text.strip()
            if "{" in raw_text:
                raw_text = raw_text[raw_text.find("{"):raw_text.rfind("}") + 1]
            
            ai_data = json.loads(raw_text)
            findings = ai_data.get("findings", [])

            # Phase 2: Autonomous Exploit Generation
            # We enrich findings with live PoCs for high-confidence issues
            enriched_findings = []
            for f in findings:
                if f.get("confidence", 0) >= 0.7:
                    print(f"[*] Generating Exploit PoC for: {f['title']}")
                    poc = await self.exploit_gen.generate_poc(
                        f['title'], 
                        f.get('url', target), 
                        f.get('evidence')
                    )
                    f['poc_details'] = poc
                enriched_findings.append(f)

            report = {
                "target": target,
                "summary": {
                    "total_raw": len(vulnerabilities),
                    "verified": len(enriched_findings),
                    "critical": len([v for v in enriched_findings if v.get('severity') == 'Critical']),
                    "high": len([v for v in enriched_findings if v.get('severity') == 'High'])
                },
                "findings": enriched_findings
            }
            return report

        except Exception as e:
            print(f"[!] Intelligence System Error: {e}")
            return {
                "target": target, 
                "status": "error",
                "message": "AI System failed to process findings.",
                "raw_data": vulnerabilities
            }