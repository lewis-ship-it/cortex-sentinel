import os
import json
import asyncio
import logging
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()


# -------------------------------
# SAFE JSON PARSER
# -------------------------------
def safe_json_parse(text):
    try:
        if "{" in text:
            text = text[text.find("{"):text.rfind("}") + 1]
        return json.loads(text)
    except Exception:
        return None


# -------------------------------
# EXPLOIT GENERATOR
# -------------------------------
class ExploitGenerator:
    def __init__(self, model):
        self.model = model

    async def generate_poc(self, vuln_type, url, evidence=None):
        prompt = f"""
        Target: {url}
        Vulnerability: {vuln_type}
        Context: {evidence}

        TASK:
        1. Provide a working payload
        2. Provide a curl command
        3. Explain bypass logic briefly

        Return JSON:
        {{
          "payload": "...",
          "curl_command": "...",
          "explanation": "..."
        }}
        """

        try:
            response = await asyncio.to_thread(self.model.generate_content, prompt)
            parsed = safe_json_parse(response.text)
            return parsed if parsed else {"error": "Invalid PoC format"}
        except Exception as e:
            return {"error": str(e)}


# -------------------------------
# AI REPORT GENERATOR
# -------------------------------
class AIReportGenerator:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        genai.configure(api_key=api_key)

        self.model = genai.GenerativeModel('gemini-1.5-flash')
        self.exploit_gen = ExploitGenerator(self.model)

    async def generate_report(self, data, target):
        """
        Accepts:
        {
            findings: [],
            attack_graph: {},
            chains: []
        }
        """

        findings = data.get("findings", [])
        attack_graph = data.get("attack_graph", {})
        chains = data.get("chains", [])

        if not findings:
            return {
                "target": target,
                "summary": "No vulnerabilities found.",
                "findings": []
            }

        # -------------------------------
        # AI REASONING PROMPT (UPGRADED)
        # -------------------------------
        prompt = f"""
        You are an elite penetration tester.

        TARGET: {target}

        DATA:
        Findings:
        {json.dumps(findings, indent=2)}

        Attack Graph:
        {json.dumps(attack_graph, indent=2)}

        Exploit Chains:
        {json.dumps(chains, indent=2)}

        Task:
        1. Provide a SAFE example payload (non-destructive).
        2. Provide a demonstration request (no real exploitation).
        3. Explain the vulnerability.

        Do NOT provide weaponized or destructive payloads.

        OUTPUT JSON:
        {{
          "critical_paths": [],
          "findings": [],
          "recommendations": []
        }}
        """

        try:
            response = await asyncio.to_thread(self.model.generate_content, prompt)

            ai_data = safe_json_parse(response.text)

            if not ai_data:
                raise Exception("AI returned invalid JSON")

            refined_findings = ai_data.get("findings", [])

            # -------------------------------
            # GENERATE POCs (SMART FILTER)
            # -------------------------------
            enriched = []
            for f in refined_findings:
                confidence = float(f.get("confidence", 0.5))

                if confidence >= 0.7:
                    logging.info(f"[AI] Generating PoC for {f.get('title')}")

                    poc = await self.exploit_gen.generate_poc(
                        f.get("title"),
                        f.get("url", target),
                        f.get("evidence")
                    )

                    f["poc"] = poc

                enriched.append(f)

            # -------------------------------
            # NORMALIZE SEVERITY
            # -------------------------------
            for f in enriched:
                sev = str(f.get("severity", "Low")).capitalize()
                if sev not in ["Critical", "High", "Medium", "Low"]:
                    sev = "Medium"
                f["severity"] = sev

            # -------------------------------
            # FINAL REPORT
            # -------------------------------
            report = {
                "target": target,
                "summary": {
                    "total_findings": len(findings),
                    "validated_findings": len(enriched),
                    "critical": len([f for f in enriched if f["severity"] == "Critical"]),
                    "high": len([f for f in enriched if f["severity"] == "High"]),
                    "chains_detected": len(chains)
                },
                "critical_paths": ai_data.get("critical_paths", []),
                "findings": enriched,
                "recommendations": ai_data.get("recommendations", [])
            }

            return report

        except Exception as e:
            logging.error(f"[AI ERROR] {e}")

            return {
                "target": target,
                "status": "fallback",
                "message": "AI failed, returning raw structured data",
                "findings": findings,
                "attack_graph": attack_graph,
                "chains": chains
            }