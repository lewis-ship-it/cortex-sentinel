"""
scanner/ai_brain.py

AI Analysis using local Ollama (qwen2.5-coder:1.5b).
NO external API keys needed. All processing is local.
"""

import os
import json
import asyncio
import httpx
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from dotenv import load_dotenv
from core.logger import get_logger

load_dotenv()

logger = get_logger("ai_brain")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://host.docker.internal:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen2.5-coder:1.5b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "60"))
OLLAMA_TEMPERATURE = float(os.getenv("OLLAMA_TEMPERATURE", "0.7"))

@dataclass
class ValidationResult:
    """Data class for validation results."""
    valid: bool
    confidence: float
    reason: str
    severity: str
    exploitability: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "valid": self.valid,
            "confidence": self.confidence,
            "reason": self.reason,
            "severity": self.severity,
            "exploitability": self.exploitability
        }

class AIError(Exception):
    """Custom exception for AI-related errors."""
    pass

async def _call_ollama(prompt: str, job_id: str = "system", **kwargs) -> str:
    """
    Call local Ollama model via HTTP API.
    
    Args:
        prompt: Input prompt for the model
        job_id: Job ID for logging
        **kwargs: Additional parameters for the API call
        
    Returns:
        Model response text
    """
    try:
        url = f"{OLLAMA_HOST}/api/generate"
        model = kwargs.get("model", MODEL_NAME)
        temperature = kwargs.get("temperature", OLLAMA_TEMPERATURE)
        timeout = kwargs.get("timeout", OLLAMA_TIMEOUT)
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                url,
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": temperature,
                    **{k: v for k, v in kwargs.items() if k not in ['model', 'temperature', 'timeout']}
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "")
            else:
                error_msg = f"Ollama API error: {response.status_code} - {response.text}"
                logger.error(error_msg, job_id)
                raise AIError(error_msg)
                
    except httpx.TimeoutException:
        error_msg = "Ollama request timed out"
        logger.error(error_msg, job_id)
        raise AIError(error_msg)
    except Exception as e:
        error_msg = f"Ollama connection failed: {str(e)}"
        logger.error(error_msg, job_id)
        raise AIError(error_msg)

def _extract_json(text: str) -> Dict[str, Any]:
    """
    Extract JSON from model response (handles markdown code blocks, etc).
    
    Args:
        text: Response text potentially containing JSON
        
    Returns:
        Parsed JSON dict, or empty dict if extraction fails
    """
    if not text:
        return {}
    
    # Clean the text first
    cleaned_text = text.strip()
    
    try:
        # Try direct JSON parse first
        return json.loads(cleaned_text)
    except json.JSONDecodeError:
        pass
    
    # Extract from markdown code blocks
    json_blocks = []
    
    # Handle ```json blocks
    if "```json" in cleaned_text:
        parts = cleaned_text.split("```json")
        for part in parts[1:]:
            end_block = part.find("```")
            if end_block > 0:
                json_block = part[:end_block].strip()
                json_blocks.append(json_block)
    
    # Handle generic ``` blocks
    if "```" in cleaned_text:
        parts = cleaned_text.split("```")
        for i, part in enumerate(parts):
            if i % 2 == 1:  # Odd indices are code blocks
                json_blocks.append(part.strip())
    
    # Try parsing each extracted block
    for block in json_blocks:
        try:
            return json.loads(block)
        except json.JSONDecodeError:
            pass
    
    # Try to find JSON object in text
    try:
        # Look for the first { and last } in the entire text
        start = cleaned_text.find('{')
        end = cleaned_text.rfind('}')
        
        if start >= 0 and end > start:
            json_str = cleaned_text[start:end+1]
            return json.loads(json_str)
    except json.JSONDecodeError:
        pass
    
    return {}

def _create_default_validation_result(finding: Dict[str, Any], 
                                    valid: bool = True, 
                                    confidence: float = 0.5, 
                                    reason: str = "AI analysis unavailable") -> Dict[str, Any]:
    """Create a default validation result."""
    return ValidationResult(
        valid=valid,
        confidence=confidence,
        reason=reason,
        severity=finding.get("severity", "Medium"),
        exploitability=0.5
    ).to_dict()

class AIBrain:
    """
    Local AI analysis using Ollama (qwen2.5-coder:1.5b).
    All processing is done on-device, no external APIs needed.
    """
    
    def __init__(self, job_id: str = "system"):
        self.job_id = job_id
        self.model = MODEL_NAME
        self.ollama_host = OLLAMA_HOST
        self.timeout = OLLAMA_TIMEOUT
        self.temperature = OLLAMA_TEMPERATURE
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
            response = await _call_ollama(prompt, self.job_id, 
                                        temperature=0.5)  # Lower temp for validation
            result = _extract_json(response)
            
            # Ensure required fields with proper validation
            if not result or not isinstance(result, dict):
                return _create_default_validation_result(finding)
            
            # Validate and sanitize the result
            validated_result = {
                "valid": bool(result.get("valid", True)),
                "confidence": max(0.0, min(1.0, float(result.get("confidence", 0.5)))),
                "reason": str(result.get("reason", "AI analysis completed")),
                "severity": str(result.get("severity", finding.get("severity", "Medium"))),
                "exploitability": max(0.0, min(1.0, float(result.get("exploitability", 0.5))))
            }
            
            logger.debug(f"Finding validated: {validated_result.get('valid')}", self.job_id)
            return validated_result
            
        except Exception as e:
            logger.error(f"Validation failed: {str(e)}", self.job_id)
            return _create_default_validation_result(finding, 
                                                   reason=f"AI error: {str(e)}",
                                                   confidence=0.3)
    
    async def generate_payloads(self, context: str, count: int = 5) -> list:
        """
        Generate advanced test payloads for the given context.
        
        Args:
            context: Target context (tech stack, parameters, etc)
            count: Number of payloads to generate (default: 5)
            
        Returns:
            List of payload strings
        """
        prompt = f"""You are an advanced exploit developer. Generate {count} advanced payloads.

Target context:
{context}

Focus on SQL Injection, XSS, or SSTI depending on context.

Respond with ONLY valid JSON (no markdown):
{{
  "payloads": ["payload1", "payload2", "payload3", "payload4", "payload5"]
}}"""
        
        try:
            response = await _call_ollama(prompt, self.job_id,
                                        temperature=0.8)  # Higher temp for creativity
            result = _extract_json(response)
            
            # Extract and validate payloads
            payloads = result.get("payloads", [])
            if not isinstance(payloads, list):
                payloads = []
            
            # Sanitize payloads (basic validation)
            sanitized_payloads = []
            for payload in payloads[:count]:
                if isinstance(payload, str) and payload.strip():
                    sanitized_payloads.append(payload.strip())
            
            logger.info(f"Generated {len(sanitized_payloads)} payloads", self.job_id)
            return sanitized_payloads
            
        except Exception as e:
            logger.error(f"Payload generation failed: {str(e)}", self.job_id)
            return []
    
    async def analyze_attack_chain(self, findings: list, max_findings: int = 10) -> dict:
        """
        Analyze and identify attack chains from findings.
        
        Args:
            findings: List of vulnerability findings
            max_findings: Maximum number of findings to analyze
            
        Returns:
            Attack chain analysis
        """
        findings_str = json.dumps(findings[:max_findings], indent=2)
        
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
            response = await _call_ollama(prompt, self.job_id,
                                        temperature=0.6)
            result = _extract_json(response)
            
            if not result or not isinstance(result, dict):
                result = {"chains": []}
            
            # Validate chains structure
            chains = result.get("chains", [])
            if not isinstance(chains, list):
                chains = []
            
            validated_chains = []
            for chain in chains:
                if isinstance(chain, dict):
                    validated_chains.append({
                        "steps": chain.get("steps", []),
                        "impact": chain.get("impact", "Unknown"),
                        "severity": chain.get("severity", "Medium"),
                        "likelihood": max(0.0, min(1.0, float(chain.get("likelihood", 0.5))))
                    })
            
            result["chains"] = validated_chains
            
            logger.info(f"Identified {len(validated_chains)} attack chains", self.job_id)
            return result
            
        except Exception as e:
            logger.error(f"Chain analysis failed: {str(e)}", self.job_id)
            return {"chains": []}
    
    async def prioritize_targets(self, endpoints: list, max_endpoints: int = 20) -> list:
        """
        Prioritize endpoints by vulnerability likelihood.
        
        Args:
            endpoints: List of endpoint URLs
            max_endpoints: Maximum number of endpoints to prioritize
            
        Returns:
            Prioritized list of URLs
        """
        endpoints_str = json.dumps(endpoints[:max_endpoints], indent=2)
        
        prompt = f"""You are a web security expert. Rank these endpoints by vulnerability likelihood:

{endpoints_str}

Consider parameter names, methods, and common patterns.

Respond with ONLY valid JSON (no markdown):
{{
  "priority": ["url1", "url2", "url3"]
}}"""
        
        try:
            response = await _call_ollama(prompt, self.job_id,
                                        temperature=0.4)  # Lower temp for ranking
            result = _extract_json(response)
            
            priority = result.get("priority", endpoints[:max_endpoints])
            if not isinstance(priority, list):
                priority = endpoints[:max_endpoints]
            
            # Validate URLs and limit results
            validated_priority = []
            for url in priority:
                if isinstance(url, str) and url.strip():
                    validated_priority.append(url.strip())
            
            logger.info(f"Prioritized {len(validated_priority)} endpoints", self.job_id)
            return validated_priority[:10]  # Limit to 10
            
        except Exception as e:
            logger.error(f"Prioritization failed: {str(e)}", self.job_id)
            return endpoints[:10]
    
    async def generate_report_summary(self, findings: list, target: str, max_findings: int = 15) -> str:
        """
        Generate executive summary for security report.
        
        Args:
            findings: List of vulnerabilities
            target: Target URL
            max_findings: Maximum number of findings to include
            
        Returns:
            Executive summary text
        """
        findings_str = json.dumps(findings[:max_findings], indent=2)
        
        prompt = f"""You are a security consultant writing a brief executive summary.

Target: {target}
Vulnerabilities found: {len(findings)}

{findings_str}

Write a 2-3 sentence executive summary highlighting the most critical risks and recommended immediate actions.

Be direct and actionable."""
        
        try:
            response = await _call_ollama(prompt, self.job_id,
                                        temperature=0.3)  # Lower temp for formal writing
            summary = response.strip()
            
            # Basic validation and cleanup
            if not summary or len(summary) < 10:
                summary = f"Security scan identified {len(findings)} vulnerabilities requiring immediate remediation."
            
            logger.info("Generated report summary", self.job_id)
            return summary
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}", self.job_id)
            return f"Security scan identified {len(findings)} vulnerabilities requiring immediate remediation."


# Singleton instance
_brain: Optional[AIBrain] = None

def get_ai_brain(job_id: str = "system") -> AIBrain:
    """Get or create AIBrain instance."""
    global _brain
    if _brain is None or _brain.job_id != job_id:
        _brain = AIBrain(job_id)
    return _brain
