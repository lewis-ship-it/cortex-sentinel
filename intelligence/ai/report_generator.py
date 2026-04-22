# intelligence/ai/report_generator.py
# ──────────────────────────────────────────────────────────────────────────────
# REPORT GENERATOR — powered exclusively by local Ollama / qwen2.5-coder.
# google.generativeai has been REMOVED. No external fallback.
# ──────────────────────────────────────────────────────────────────────────────

import json
import logging
from scanner.ai_brain import _call_ollama, _extract_json

logger = logging.getLogger(__name__)


class AIReportGenerator:
    """
    Executive report generator using the internal AIBrain / Ollama stack.
    If Ollama is unreachable this will raise — that is the intended behaviour.
    """

    async def generate_report(self, data: dict, target: str) -> dict:
        findings = data.get("findings", [])

        if not findings:
            return self._empty_report(target)

        compact_findings = [
            {
                "type":     f.get("type"),
                "severity": f.get("severity"),
                "url":      f.get("url") or f.get("target_url"),
                "evidence": str(f.get("evidence", ""))[:200],
            }
            for f in findings
        ]

        prompt = f"""
Act as a Lead Security Consultant. Review this DAST scan for {target}.

FINDINGS DATA:
{json.dumps(compact_findings)}

Generate a professional executive report as JSON:
{{
  "executive_summary": "3-sentence summary of security posture",
  "risk_score": 0,
  "attack_narrative": "How an attacker would chain these specific findings",
  "remediation_plan": ["High-level step 1", "High-level step 2"]
}}
"""
        # Raises on Ollama failure — no silent external fallback.
        text    = await _call_ollama(prompt)
        ai_json = _extract_json(text)

        return {
            "target": target,
            "summary": {
                "total_findings": len(findings),
                "risk_score":     ai_json.get("risk_score", 0),
                "critical_count": sum(1 for f in findings if f.get("severity") == "Critical"),
                "high_count":     sum(1 for f in findings if f.get("severity") == "High"),
            },
            "executive_content": {
                "summary":     ai_json.get("executive_summary"),
                "narrative":   ai_json.get("attack_narrative"),
                "remediation": ai_json.get("remediation_plan"),
            },
            "raw_findings": findings,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _empty_report(self, target: str) -> dict:
        return {
            "target":            target,
            "executive_summary": "No vulnerabilities were identified during this automated scan.",
            "risk_score":        0,
            "findings":          [],
        }