# intelligence/ai/report_generator.py
import os, json, asyncio, logging
import google.generativeai as genai
from dotenv import load_dotenv
from scanner.ai_brain import AIBrain

load_dotenv()
logger = logging.getLogger(__name__)


def safe_json_parse(text: str):
    try:
        s = text.find("{")
        e = text.rfind("}")
        if s >= 0 and e >= 0:
            return json.loads(text[s:e+1])
    except Exception:
        pass
    return None


class AIReportGenerator:
    def __init__(self):
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        self._model    = genai.GenerativeModel("gemini-1.5-flash")
        self.brain     = AIBrain()

    async def generate_report(self, data: dict, target: str) -> dict:
        findings     = data.get("findings", [])
        attack_graph = data.get("attack_graph", {})
        chains       = data.get("chains", [])

        if not findings:
            return {"target": target, "summary": {"total": 0}, "findings": []}

        summary = {
            "total":    len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "Critical"),
            "high":     sum(1 for f in findings if f.get("severity") == "High"),
            "medium":   sum(1 for f in findings if f.get("severity") == "Medium"),
            "low":      sum(1 for f in findings if f.get("severity") == "Low"),
        }

        prompt = f"""You are a senior web application penetration tester writing a professional security report.

TARGET: {target}

VERIFIED FINDINGS ({len(findings)} total):
{json.dumps(findings, indent=2)}

ATTACK CHAINS:
{json.dumps(chains, indent=2)}

For each finding provide:
1. Clear technical explanation of the vulnerability
2. Exact reproduction steps
3. Real-world business impact
4. Specific remediation code or configuration

Return ONLY valid JSON in this exact structure:
{{
  "executive_summary": "2-3 sentence business-level summary",
  "findings": [
    {{
      "type": "...",
      "severity": "Critical|High|Medium|Low",
      "url": "...",
      "parameter": "...",
      "payload": "...",
      "confidence": 0.0-1.0,
      "description": "technical explanation",
      "impact": "business impact",
      "reproduction": ["step 1", "step 2"],
      "remediation": "specific fix with code example",
      "cwe": "CWE-XX",
      "cvss": 0.0-10.0
    }}
  ],
  "recommendations": ["priority fix 1", "priority fix 2"],
  "attack_narrative": "how these findings chain together"
}}"""

        try:
            res     = await asyncio.to_thread(self._model.generate_content, prompt)
            ai_data = safe_json_parse(res.text)
            if not ai_data:
                raise ValueError("AI returned unparseable response")

            # Normalize severities
            for f in ai_data.get("findings", []):
                sev = str(f.get("severity","Low")).capitalize()
                if sev not in ("Critical","High","Medium","Low"):
                    sev = "Medium"
                f["severity"] = sev

            return {
                "target":            target,
                "summary":           summary,
                "executive_summary": ai_data.get("executive_summary",""),
                "findings":          ai_data.get("findings", findings),
                "recommendations":   ai_data.get("recommendations", []),
                "attack_narrative":  ai_data.get("attack_narrative",""),
                "attack_graph":      attack_graph,
                "chains":            chains,
            }

        except Exception as e:
            logger.error(f"[AI REPORT] Error: {e}")
            return {
                "target":   target,
                "summary":  summary,
                "findings": findings,
                "status":   "fallback",
            }
