# scanner/ai_report.py
# ──────────────────────────────────────────────────────────────────────────────
# AI REPORT GENERATOR — powered exclusively by local Ollama / qwen2.5-coder.
# No external provider. No fallback. Failure is loud and intentional.
# ──────────────────────────────────────────────────────────────────────────────

import json
import asyncio
import logging
import httpx
from dotenv import load_dotenv
from scanner.ai_brain import AIBrain, _call_ollama, _extract_json

load_dotenv()

logger = logging.getLogger(__name__)


class ExploitGenerator:
    """Generates safe proof-of-concept payloads via the local Ollama model."""

    async def generate_poc(self, vuln_type: str, url: str, evidence=None) -> dict:
        prompt = f"""
Target: {url}
Vulnerability: {vuln_type}
Context: {evidence}

TASK:
1. Provide a working payload (non-destructive / demonstration only).
2. Provide a curl command.
3. Explain bypass logic briefly.

Return JSON:
{{
  "payload": "...",
  "curl_command": "...",
  "explanation": "..."
}}
"""
        text = await _call_ollama(prompt)
        parsed = _extract_json(text)
        return parsed if parsed else {"error": "Invalid PoC format from model"}


class AIReportGenerator:
    """
    Orchestrates AI-powered security report generation.
    Uses AIBrain (Ollama) exclusively — no Gemini, no OpenAI, no fallback.
    """

    def __init__(self):
        self.brain = AIBrain()
        self.exploit_gen = ExploitGenerator()

    async def generate_report(self, data: dict, target: str, tier: str = "Professional") -> dict:
        findings     = data.get("findings", [])
        attack_graph = data.get("attack_graph", {})
        chains       = data.get("chains", [])

        if not findings:
            return {
                "target":   target,
                "summary":  "No vulnerabilities found.",
                "findings": [],
            }

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
You are an elite penetration tester writing a professional security report.

TARGET: {target}

FINDINGS:
{json.dumps(compact_findings, indent=2)}

ATTACK GRAPH:
{json.dumps(attack_graph, indent=2)}

EXPLOIT CHAINS:
{json.dumps(chains, indent=2)}

TASKS:
1. Provide a SAFE example payload (non-destructive).
2. Provide a demonstration request (no real exploitation).
3. Explain each vulnerability clearly.
4. Provide prioritised remediation steps.

OUTPUT STRICTLY AS JSON:
{{
  "executive_summary": "3-sentence summary of security posture",
  "risk_score": 0,
  "attack_narrative": "How an attacker would chain these findings",
  "remediation_plan": ["Step 1", "Step 2"],
  "critical_paths": [],
  "findings": [],
  "recommendations": []
}}
"""
        # This will raise httpx.ConnectError if Ollama is down — intentional.
        text    = await _call_ollama(prompt)
        ai_data = _extract_json(text)

        refined_findings = ai_data.get("findings", [])

        # Enrich high-confidence findings with PoC
        enriched = []
        for f in refined_findings:
            if float(f.get("confidence", 0.5)) >= 0.7:
                logger.info(f"[AI] Generating PoC for {f.get('title')}")
                poc = await self.exploit_gen.generate_poc(
                    f.get("title"),
                    f.get("url", target),
                    f.get("evidence"),
                )
                f["poc"] = poc

            sev = str(f.get("severity", "Low")).capitalize()
            if sev not in ("Critical", "High", "Medium", "Low"):
                sev = "Medium"
            f["severity"] = sev
            enriched.append(f)

        return {
            "target": target,
            "summary": {
                "total_findings":     len(findings),
                "validated_findings": len(enriched),
                "critical":           sum(1 for f in enriched if f.get("severity") == "Critical"),
                "high":               sum(1 for f in enriched if f.get("severity") == "High"),
                "chains_detected":    len(chains),
                "risk_score":         ai_data.get("risk_score", 0),
            },
            "executive_content": {
                "summary":     ai_data.get("executive_summary"),
                "narrative":   ai_data.get("attack_narrative"),
                "remediation": ai_data.get("remediation_plan"),
            },
            "critical_paths":   ai_data.get("critical_paths", []),
            "findings":         enriched,
            "recommendations":  ai_data.get("recommendations", []),
        }