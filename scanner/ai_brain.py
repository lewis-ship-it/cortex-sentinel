"""
scanner/ai_brain.py

AI Analysis using local Ollama (qwen2.5-coder:1.5b).
NO external API keys needed. All processing is local.
"""

import os
import json
import asyncio
import httpx
from dotenv import load_dotenv
from core.logger import get_logger

load_dotenv()

logger = get_logger("ai_brain")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen2.5-coder:1.5b")


async def _call_ollama(prompt: str, job_id: str = "system") -> str:
    """
    Call local Ollama model via HTTP API.
    
    Args:
        prompt: Input prompt for the model
        job_id: Job ID for logging
        
    Returns:
        Model response text
    """
    try:
        url = f"{OLLAMA_HOST}/api/generate"
        
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                url,
                json={
                    "model": MODEL_NAME,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.7
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "")
            else:
                logger.error(f"Ollama API error: {response.status_code}", job_id)
                return ""
                
    except Exception as e:
        logger.error(f"Ollama connection failed: {str(e)}", job_id)
        return ""


def _extract_json(text: str) -> dict:
    """
    Extract JSON from model response (handles markdown code blocks, etc).
    
    Args:
        text: Response text potentially containing JSON
        
    Returns:
        Parsed JSON dict, or empty dict if extraction fails
    """
    try:
        # Try direct JSON parse first
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    
    # Extract from markdown code block
    if "```json" in text:
        start = text.find("```json") + 7
        end = text.find("```", start)
        if end > start:
            try:
                return json.loads(text[start:end].strip())
            except Exception:
                pass
    
    # Extract from code block without language
    if "```" in text:
        parts = text.split("```")
        if len(parts) >= 2:
            try:
                return json.loads(parts[1].strip())
            except Exception:
                pass
    
    # Try to find JSON object in text
    for i, char in enumerate(text):
        if char == '{':
            for j in range(len(text), i, -1):
                if text[j-1] == '}':
                    try:
                        return json.loads(text[i:j])
                    except Exception:
                        pass
    
    return {}


class AIBrain:
    """
    Local AI analysis using Ollama (qwen2.5-coder:1.5b).
    All processing is done on-device, no external APIs needed.
    """
    
    def __init__(self, job_id: str = "system"):
        self.job_id = job_id
        self.model = MODEL_NAME
        self.ollama_host = OLLAMA_HOST
        logger.info(f"AIBrain initialized with {MODEL_NAME}", job_id)
    
    async def validate_finding(self, finding: dict) -> dict:
        """
        Validate and analyze a security finding.
        
        Args:
            finding: Finding dict with type, severity, etc
            
        Returns:
            Validation result with confidence and reasoning
        """
        prompt = f"""You are a senior penetration tester. Analyze this security finding:

{json.dumps(finding, indent=2)}

Respond with ONLY valid JSON (no markdown, no explanation):
{{
  "valid": true,
  "confidence": 0.85,
  "reason": "Brief explanation",
  "severity": "High",
  "exploitability": 0.9
}}"""
        
        try:
            response = await _call_ollama(prompt, self.job_id)
            result = _extract_json(response)
            
            # Ensure required fields
            if not result:
                result = {
                    "valid": True,
                    "confidence": 0.5,
                    "reason": "AI analysis unavailable",
                    "severity": finding.get("severity", "Medium"),
                    "exploitability": 0.5
                }
            
            logger.debug(f"Finding validated: {result.get('valid')}", self.job_id)
            return result
            
        except Exception as e:
            logger.error(f"Validation failed: {str(e)}", self.job_id)
            return {
                "valid": True,
                "confidence": 0.3,
                "reason": f"AI error: {str(e)}",
                "severity": finding.get("severity", "Medium"),
                "exploitability": 0.3
            }
    
    async def generate_payloads(self, context: str) -> list:
        """
        Generate advanced test payloads for the given context.
        
        Args:
            context: Target context (tech stack, parameters, etc)
            
        Returns:
            List of payload strings
        """
        prompt = f"""You are an advanced exploit developer. Generate 5 advanced payloads.

Target context:
{context}

Focus on SQL Injection, XSS, or SSTI depending on context.

Respond with ONLY valid JSON (no markdown):
{{
  "payloads": ["payload1", "payload2", "payload3", "payload4", "payload5"]
}}"""
        
        try:
            response = await _call_ollama(prompt, self.job_id)
            result = _extract_json(response)
            payloads = result.get("payloads", [])
            
            logger.info(f"Generated {len(payloads)} payloads", self.job_id)
            return payloads[:5]  # Limit to 5
            
        except Exception as e:
            logger.error(f"Payload generation failed: {str(e)}", self.job_id)
            return []
    
    async def analyze_attack_chain(self, findings: list) -> dict:
        """
        Analyze and identify attack chains from findings.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Attack chain analysis
        """
        findings_str = json.dumps(findings[:10], indent=2)  # Limit to 10
        
        prompt = f"""You are an elite penetration tester. Analyze these vulnerabilities for attack chains:

{findings_str}

Identify realistic multi-step attack paths.

Respond with ONLY valid JSON (no markdown):
{{
  "chains": [
    {{
      "steps": ["XSS", "Session Hijack"],
      "impact": "Account takeover",
      "severity": "Critical",
      "likelihood": 0.8
    }}
  ]
}}"""
        
        try:
            response = await _call_ollama(prompt, self.job_id)
            result = _extract_json(response)
            
            if not result:
                result = {"chains": []}
            
            logger.info(f"Identified {len(result.get('chains', []))} attack chains", self.job_id)
            return result
            
        except Exception as e:
            logger.error(f"Chain analysis failed: {str(e)}", self.job_id)
            return {"chains": []}
    
    async def prioritize_targets(self, endpoints: list) -> list:
        """
        Prioritize endpoints by vulnerability likelihood.
        
        Args:
            endpoints: List of endpoint URLs
            
        Returns:
            Prioritized list of URLs
        """
        endpoints_str = json.dumps(endpoints[:20], indent=2)  # Limit to 20
        
        prompt = f"""You are a web security expert. Rank these endpoints by vulnerability likelihood:

{endpoints_str}

Consider parameter names, methods, and common patterns.

Respond with ONLY valid JSON (no markdown):
{{
  "priority": ["url1", "url2", "url3"]
}}"""
        
        try:
            response = await _call_ollama(prompt, self.job_id)
            result = _extract_json(response)
            priority = result.get("priority", endpoints)
            
            logger.info(f"Prioritized {len(priority)} endpoints", self.job_id)
            return priority[:10]  # Limit to 10
            
        except Exception as e:
            logger.error(f"Prioritization failed: {str(e)}", self.job_id)
            return endpoints[:10]
    
    async def generate_report_summary(self, findings: list, target: str) -> str:
        """
        Generate executive summary for security report.
        
        Args:
            findings: List of vulnerabilities
            target: Target URL
            
        Returns:
            Executive summary text
        """
        findings_str = json.dumps(findings[:15], indent=2)
        
        prompt = f"""You are a security consultant writing a brief executive summary.

Target: {target}
Vulnerabilities found: {len(findings)}

{findings_str}

Write a 2-3 sentence executive summary highlighting the most critical risks and recommended immediate actions.

Be direct and actionable."""
        
        try:
            response = await _call_ollama(prompt, self.job_id)
            logger.info("Generated report summary", self.job_id)
            return response.strip()
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}", self.job_id)
            return f"Security scan identified {len(findings)} vulnerabilities requiring immediate remediation."


# Singleton instance
_brain: AIBrain = None

def get_ai_brain(job_id: str = "system") -> AIBrain:
    """Get or create AIBrain instance."""
    global _brain
    if _brain is None:
        _brain = AIBrain(job_id)
    return _brain