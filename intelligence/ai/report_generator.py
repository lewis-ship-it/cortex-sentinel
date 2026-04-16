# intelligence/ai/report_generator.py
import os
import json
import asyncio
import logging
import google.generativeai as genai

logger = logging.getLogger(__name__)

class AIReportGenerator:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.error("REPORT_GEN: Missing Gemini API Key")
            
        genai.configure(api_key=api_key)
        # Using Flash for speed; reports are long, and we want them generated in seconds.
        self._model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            generation_config={"response_mime_type": "application/json"}
        )

    async def generate_report(self, data: dict, target: str) -> dict:
        findings = data.get("findings", [])
        # Critical: If there are no findings, don't waste tokens
        if not findings:
            return self._empty_report(target)

        # We pass only essential info to the AI to stay within context limits
        compact_findings = [
            {
                "type": f.get("type"),
                "severity": f.get("severity"),
                "url": f.get("url"),
                "evidence": f.get("evidence", "")[:200]
            } for f in findings
        ]

        prompt = f"""
        Act as a Lead Security Consultant. Review this DAST scan for {target}.
        
        FINDINGS DATA:
        {json.dumps(compact_findings)}
        
        Generate a professional executive report in JSON format.
        Include:
        1. executive_summary: A 3-sentence summary of the security posture.
        2. risk_score: A value from 0-100 (100 being critical risk).
        3. attack_narrative: How an attacker would chain these specific findings together.
        4. remediation_plan: High-level steps for the engineering team.
        """

        try:
            # Use the faster async call
            res = await self._model.generate_content_async(prompt)
            ai_json = json.loads(res.text)
            
            # Final assembly of the report object
            return {
                "target": target,
                "summary": {
                    "total_findings": len(findings),
                    "risk_score": ai_json.get("risk_score", 0),
                    "critical_count": sum(1 for f in findings if f.get("severity") == "Critical"),
                    "high_count": sum(1 for f in findings if f.get("severity") == "High"),
                },
                "executive_content": {
                    "summary": ai_json.get("executive_summary"),
                    "narrative": ai_json.get("attack_narrative"),
                    "remediation": ai_json.get("remediation_plan")
                },
                "raw_findings": findings
            }
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return self._fallback_report(target, findings)

    def _empty_report(self, target):
        return {
            "target": target,
            "executive_summary": "No vulnerabilities were identified during this automated scan.",
            "risk_score": 0,
            "findings": []
        }

    def _fallback_report(self, target, findings):
        return {
            "target": target,
            "status": "partial_failure",
            "findings": findings,
            "executive_summary": "Report generated without AI insights due to technical error."
        }