# intelligence/ai_brain.py
# ──────────────────────────────────────────────────────────────────────────────
# ENHANCED AI BRAIN — Advanced security intelligence with local Ollama
# Features: Advanced attack surface analysis, ML-based validation, 
# exploit chain generation, and threat intelligence integration
# ──────────────────────────────────────────────────────────────────────────────

import json
import logging
import re
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from scanner.ai_brain import _call_ollama, _extract_json

logger = logging.getLogger(__name__)

# Advanced pattern database for attack surface analysis
ATTACK_PATTERNS = {
    "sql_injection": {
        "params": ["id", "user", "account", "search", "filter", "query", "sort", "category"],
        "indicators": ["numeric_id", "string_input", "search_field"],
        "risk_level": "High"
    },
    "xss": {
        "params": ["q", "search", "term", "name", "comment", "message", "content"],
        "indicators": ["text_input", "comment_field", "user_content"],
        "risk_level": "High"
    },
    "ssrf": {
        "params": ["url", "file", "path", "image", "load", "fetch", "proxy"],
        "indicators": ["url_parameter", "file_reference", "external_resource"],
        "risk_level": "Critical"
    },
    "idor": {
        "params": ["id", "user_id", "account_id", "document_id", "order_id", "invoice_id"],
        "indicators": ["uuid_pattern", "numeric_id", "sequential_id"],
        "risk_level": "High"
    },
    "lfi": {
        "params": ["file", "path", "include", "load", "template", "view"],
        "indicators": ["file_reference", "path_traversal", "template_include"],
        "risk_level": "Critical"
    },
    "rce": {
        "params": ["cmd", "command", "exec", "system", "code", "eval"],
        "indicators": ["command_input", "code_execution", "system_call"],
        "risk_level": "Critical"
    }
}

# Technology stack detection patterns
TECHNOLOGY_PATTERNS = {
    "php": ["\\.php", "phpsessid", "x-powered-by: php", "php\\/"],
    "nodejs": ["node\\.js", "express", "x-powered-by: express", "npm"],
    "python": ["python", "django", "flask", "wsgi", "x-powered-by: python"],
    "java": ["java", "jsp", "servlet", "spring", "jboss", "tomcat"],
    "dotnet": ["\\.aspx", "\\.ashx", "asp\\.net", "iis", "x-aspnet-version"],
    "ruby": ["ruby", "rails", "rack", "x-powered-by: ruby"],
    "wordpress": ["wp-", "wordpress", "wp_content", "wp_includes"],
    "drupal": ["drupal", "sites/all/", "x-generator: drupal"],
}

class AIBrain:
    """
    Enhanced Intelligence-layer AI Brain with advanced security analysis capabilities.
    Uses local Ollama exclusively with sophisticated prompt engineering.
    """

    def __init__(self):
        self.analysis_cache = {}
        self.request_count = 0
        self.last_request_time = None

    async def analyze_attack_surface(self, crawl_data: list, target_url: str = None) -> list:
        """
        Advanced attack surface analysis with technology detection and risk assessment.
        """
        # Cache check
        cache_key = f"attack_surface_{hash(str(crawl_data))}"
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        try:
            # Pre-process and filter endpoints
            filtered_endpoints = self._preprocess_endpoints(crawl_data, target_url)
            
            # Technology stack detection
            tech_stack = await self._detect_technology_stack(filtered_endpoints)
            
            # Advanced AI analysis
            prompt = self._build_attack_surface_prompt(filtered_endpoints, tech_stack, target_url)
            
            text = await self._call_ollama_with_retry(prompt)
            result = _extract_json(text)
            
            if isinstance(result, list):
                # Enhance results with additional analysis
                enhanced_results = await self._enhance_attack_analysis(result, filtered_endpoints, tech_stack)
                self.analysis_cache[cache_key] = enhanced_results
                return enhanced_results
            
            return []
            
        except Exception as e:
            logger.error(f"Attack surface analysis failed: {e}")
            return self._fallback_attack_analysis(crawl_data)

    def _preprocess_endpoints(self, crawl_data: list, target_url: str) -> list:
        """Pre-process and filter endpoints for analysis"""
        processed = []
        base_domain = self._extract_domain(target_url) if target_url else None
        
        for endpoint in crawl_data:
            if not isinstance(endpoint, dict):
                continue
                
            url = endpoint.get('url', '')
            method = endpoint.get('method', 'GET')
            params = endpoint.get('params', {})
            
            # Filter by domain if target_url provided
            if base_domain and base_domain not in url:
                continue
                
            # Analyze parameters for attack potential
            param_analysis = self._analyze_parameters(params, url)
            
            processed.append({
                'url': url,
                'method': method,
                'params': params,
                'param_analysis': param_analysis,
                'technology_hints': self._detect_technology_hints(url, endpoint.get('headers', {}))
            })
        
        return processed[:100]  # Limit to top 100 endpoints

    def _analyze_parameters(self, params: dict, url: str) -> dict:
        """Analyze parameters for attack potential"""
        analysis = {}
        
        for param_name, param_value in params.items():
            param_risk = self._assess_parameter_risk(param_name, param_value, url)
            if param_risk['risk_level'] != 'Low':
                analysis[param_name] = param_risk
        
        return analysis

    def _assess_parameter_risk(self, param_name: str, param_value: Any, url: str) -> dict:
        """Assess risk level for a parameter"""
        param_name_lower = param_name.lower()
        param_str = str(param_value).lower() if param_value else ""
        
        for vuln_type, patterns in ATTACK_PATTERNS.items():
            # Check parameter name patterns
            name_matches = any(pattern in param_name_lower for pattern in patterns["params"])
            
            # Check parameter value patterns
            value_matches = False
            if param_value:
                if vuln_type == "idor":
                    value_matches = self._detect_id_patterns(param_str)
                elif vuln_type == "sql_injection":
                    value_matches = self._detect_sql_patterns(param_str)
            
            if name_matches or value_matches:
                return {
                    "vulnerability_type": vuln_type,
                    "risk_level": patterns["risk_level"],
                    "confidence": 0.7 if name_matches else 0.4,
                    "indicators": patterns["indicators"]
                }
        
        return {"risk_level": "Low", "confidence": 0.9}

    def _detect_id_patterns(self, value: str) -> bool:
        """Detect ID-like patterns for IDOR detection"""
        # UUID pattern
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return True
        
        # Numeric ID pattern
        if re.match(r'^\d+$', value):
            return True
            
        # Base64-like pattern
        if re.match(r'^[A-Za-z0-9+/=]{20,}$', value):
            return True
            
        return False

    def _detect_sql_patterns(self, value: str) -> bool:
        """Detect SQL-like patterns in parameter values"""
        sql_keywords = ['select', 'insert', 'update', 'delete', 'union', 'drop', 'alter', 'exec']
        return any(keyword in value for keyword in sql_keywords)

    async def _detect_technology_stack(self, endpoints: list) -> dict:
        """Detect technology stack from endpoints and headers"""
        tech_indicators = {tech: 0 for tech in TECHNOLOGY_PATTERNS.keys()}
        
        for endpoint in endpoints:
            url = endpoint.get('url', '').lower()
            headers = endpoint.get('headers', {})
            
            for tech, patterns in TECHNOLOGY_PATTERNS.items():
                # Check URL patterns
                if any(re.search(pattern, url, re.I) for pattern in patterns):
                    tech_indicators[tech] += 2
                
                # Check header patterns
                header_str = str(headers).lower()
                if any(re.search(pattern, header_str, re.I) for pattern in patterns):
                    tech_indicators[tech] += 3
        
        # Get top technologies
        detected_tech = {tech: score for tech, score in tech_indicators.items() if score > 0}
        sorted_tech = sorted(detected_tech.items(), key=lambda x: x[1], reverse=True)
        
        return {
            "primary_technologies": [tech for tech, score in sorted_tech[:3]],
            "confidence_scores": dict(sorted_tech[:5])
        }

    def _build_attack_surface_prompt(self, endpoints: list, tech_stack: dict, target_url: str) -> str:
        """Build sophisticated prompt for attack surface analysis"""
        sample_endpoints = json.dumps(endpoints[:20], indent=2)
        
        return f"""
As a senior security analyst, perform comprehensive attack surface analysis.

TARGET: {target_url or "Unknown"}
TECHNOLOGY STACK: {json.dumps(tech_stack, indent=2)}

ENDPOINTS SAMPLE (20 of {len(endpoints)}):
{sample_endpoints}

ANALYSIS REQUIREMENTS:
1. Identify high-risk endpoints for SQLi, XSS, SSRF, IDOR, LFI, RCE
2. Consider technology-specific vulnerabilities
3. Assess parameter patterns and business context
4. Prioritize based on potential impact
5. Include exploitation likelihood

RETURN JSON format:
{{
  "high_risk_endpoints": [
    {{
      "url": "string",
      "method": "string",
      "primary_risk": "string",
      "secondary_risks": ["string"],
      "confidence": 0.0,
      "exploitation_complexity": "Low/Medium/High",
      "business_impact": "Low/Medium/High/Critical",
      "recommended_tests": ["string"]
    }}
  ],
  "technology_specific_risks": [
    {{
      "technology": "string",
      "vulnerabilities": ["string"],
      "confidence": 0.0
    }}
  ],
  "overall_risk_assessment": {{
    "score": 0.0,
    "level": "Low/Medium/High/Critical",
    "key_findings": ["string"]
  }}
}}
"""

    async def _enhance_attack_analysis(self, results: list, endpoints: list, tech_stack: dict) -> list:
        """Enhance AI analysis with additional security intelligence"""
        enhanced_results = []
        
        for result in results:
            if not isinstance(result, dict):
                continue
                
            # Add technology context
            result['technology_context'] = self._add_technology_context(result, tech_stack)
            
            # Add CVE references if available
            result['cve_references'] = await self._find_cve_references(result)
            
            # Add exploitability assessment
            result['exploitability'] = self._assess_exploitability(result)
            
            enhanced_results.append(result)
        
        return enhanced_results

    def _add_technology_context(self, result: dict, tech_stack: dict) -> list:
        """Add technology-specific vulnerability context"""
        tech_context = []
        url = result.get('url', '').lower()
        
        for tech in tech_stack.get('primary_technologies', []):
            if tech in ['php'] and any(p in url for p in ['.php', 'php=']):
                tech_context.extend([
                    "PHP: Check for type juggling issues",
                    "PHP: Review file inclusion vulnerabilities",
                    "PHP: Assess deserialization risks"
                ])
            elif tech in ['nodejs']:
                tech_context.extend([
                    "Node.js: Check for prototype pollution",
                    "Node.js: Review package vulnerabilities",
                    "Node.js: Assess middleware security"
                ])
            elif tech in ['wordpress']:
                tech_context.extend([
                    "WordPress: Check plugin vulnerabilities",
                    "WordPress: Review theme security",
                    "WordPress: Assess core updates"
                ])
        
        return tech_context[:3]  # Return top 3

    async def validate_finding(self, finding: dict, original_res: str = "", attack_res: str = "") -> dict:
        """
        Advanced validation with machine learning-style analysis and false positive reduction.
        """
        try:
            # Build comprehensive validation prompt
            prompt = self._build_validation_prompt(finding, original_res, attack_res)
            
            text = await self._call_ollama_with_retry(prompt)
            validation_result = _extract_json(text)
            
            if isinstance(validation_result, dict):
                # Enhance with additional validation checks
                enhanced_validation = self._enhance_validation_result(validation_result, finding, original_res, attack_res)
                return enhanced_validation
            
            return self._fallback_validation_result(finding)
            
        except Exception as e:
            logger.error(f"Validation failed: {e}")
            return self._fallback_validation_result(finding)

    def _build_validation_prompt(self, finding: dict, original_res: str, attack_res: str) -> str:
        """Build sophisticated validation prompt"""
        return f"""
As a senior security validator, analyze this vulnerability finding:

FINDING:
{json.dumps(finding, indent=2)}

BASELINE RESPONSE (first 500 chars):
{original_res[:500]}

ATTACK RESPONSE (first 1000 chars):
{attack_res[:1000]}

ANALYSIS REQUIREMENTS:
1. Statistical significance of response differences
2. Evidence quality and authenticity
3. False positive indicators
4. Confidence assessment
5. Severity adjustment reasoning

Consider:
- SQL error authenticity vs custom error pages
- XSS payload execution evidence
- Timing attack statistical significance
- Response length and content changes
- HTTP status code patterns

RETURN JSON format:
{{
  "valid": boolean,
  "confidence": 0.0,
  "false_positive_indicators": ["string"],
  "true_positive_indicators": ["string"],
  "severity_adjustment": "none/upgrade/downgrade",
  "adjusted_severity": "string",
  "validation_evidence": "string",
  "recommended_actions": ["string"]
}}
"""

    def _enhance_validation_result(self, validation_result: dict, finding: dict, 
                                 original_res: str, attack_res: str) -> dict:
        """Enhance validation result with additional checks"""
        # Add response analysis
        validation_result['response_analysis'] = self._analyze_responses(original_res, attack_res)
        
        # Add confidence factors
        validation_result['confidence_factors'] = self._calculate_confidence_factors(finding, validation_result)
        
        # Add risk context
        validation_result['risk_context'] = self._assess_risk_context(finding)
        
        return validation_result

    def _analyze_responses(self, original_res: str, attack_res: str) -> dict:
        """Analyze response differences"""
        original_len = len(original_res) if original_res else 0
        attack_len = len(attack_res) if attack_res else 0
        
        return {
            "length_difference": attack_len - original_len,
            "length_change_percent": ((attack_len - original_len) / max(original_len, 1)) * 100,
            "significant_change": abs(attack_len - original_len) > 100,  # 100 char threshold
            "content_similarity": self._calculate_similarity(original_res, attack_res)
        }

    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate simple text similarity"""
        if not str1 or not str2:
            return 0.0
        
        # Simple Jaccard similarity
        set1 = set(str1.split())
        set2 = set(str2.split())
        
        if not set1 or not set2:
            return 0.0
            
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0

    async def generate_exploit_poc(self, finding: dict, safe_mode: bool = True) -> dict:
        """
        Generate advanced proof-of-concept with multiple variants and safety checks.
        """
        try:
            prompt = self._build_exploit_prompt(finding, safe_mode)
            
            text = await self._call_ollama_with_retry(prompt)
            poc_result = _extract_json(text)
            
            if isinstance(poc_result, dict):
                # Add safety checks and enhancements
                enhanced_poc = self._enhance_exploit_poc(poc_result, finding, safe_mode)
                return enhanced_poc
            
            return self._fallback_exploit_poc(finding)
            
        except Exception as e:
            logger.error(f"Exploit generation failed: {e}")
            return self._fallback_exploit_poc(finding)

    def _build_exploit_prompt(self, finding: dict, safe_mode: bool) -> str:
        """Build exploit generation prompt with safety constraints"""
        safety_clause = "NON-DESTRUCTIVE, READ-ONLY" if safe_mode else "CAUTION: DESTRUCTIVE OPERATIONS POSSIBLE"
        
        return f"""
As an ethical security researcher, generate proof-of-concept exploit commands for this vulnerability.

FINDING:
{json.dumps(finding, indent=2)}

SAFETY REQUIREMENT: {safety_clause}
- No data modification or deletion
- No system damage
- No sensitive data exposure in examples
- Use test domains (example.com, test.org)

GENERATION REQUIREMENTS:
1. Multiple exploitation variants (curl, browser, automated tools)
2. Step-by-step exploitation guide
3. Expected output patterns
4. Safety warnings and limitations
5. Verification steps

RETURN JSON format:
{{
  "poc_variants": [
    {{
      "method": "curl/httpie/browser",
      "command": "string",
      "description": "string",
      "expected_output": "string",
      "risk_level": "Low/Medium/High",
      "safety_warnings": ["string"]
    }}
  ],
  "exploitation_steps": ["string"],
  "verification_checks": ["string"],
  "defense_evasion_techniques": ["string"] (if applicable),
  "alternative_payloads": ["string"]
}}
"""

    def _enhance_exploit_poc(self, poc_result: dict, finding: dict, safe_mode: bool) -> dict:
        """Enhance exploit PoC with additional security context"""
        # Add vulnerability context
        poc_result['vulnerability_context'] = {
            "cwe_mapping": self._map_to_cwe(finding),
            "mitre_technique": self._map_to_mitre(finding),
            "exploitability": self._assess_exploitability(finding),
            "business_impact": self._assess_business_impact(finding)
        }
        
        # Add safety enhancements
        if safe_mode:
            poc_result['safety_enhancements'] = self._add_safety_enhancements(poc_result)
        
        # Add detection indicators
        poc_result['detection_indicators'] = self._add_detection_indicators(finding, poc_result)
        
        return poc_result

    def _map_to_cwe(self, finding: dict) -> list:
        """Map vulnerability to CWE categories"""
        vuln_type = finding.get('type', '').lower()
        cwe_mapping = {
            'sqli': ['CWE-89', 'CWE-564'],
            'xss': ['CWE-79', 'CWE-80'],
            'ssrf': ['CWE-918'],
            'idor': ['CWE-639'],
            'lfi': ['CWE-22', 'CWE-23'],
            'rce': ['CWE-78', 'CWE-94']
        }
        
        for vuln_pattern, cwes in cwe_mapping.items():
            if vuln_pattern in vuln_type:
                return cwes
        return ['CWE-unknown']

    def _map_to_mitre(self, finding: dict) -> str:
        """Map vulnerability to MITRE ATT&CK"""
        vuln_type = finding.get('type', '').lower()
        mitre_mapping = {
            'sqli': 'T1190',    # Exploit Public-Facing Application
            'xss': 'T1059.007', # JavaScript
            'ssrf': 'T1199',    # Trusted Relationship
            'idor': 'T1210',    # Exploitation of Remote Services
            'lfi': 'T1221',     # Template Injection
            'rce': 'T1203'      # Exploitation for Client Execution
        }
        return mitre_mapping.get(vuln_type, 'T1199')

    async def _call_ollama_with_retry(self, prompt: str, max_retries: int = 3) -> str:
        """Call Ollama with retry mechanism and rate limiting"""
        for attempt in range(max_retries):
            try:
                # Rate limiting
                if self.last_request_time:
                    elapsed = (datetime.now() - self.last_request_time).total_seconds()
                    if elapsed < 0.5:  # 500ms between requests
                        await asyncio.sleep(0.5 - elapsed)
                
                response = await _call_ollama(prompt)
                self.last_request_time = datetime.now()
                self.request_count += 1
                return response
                
            except Exception as e:
                logger.warning(f"Ollama call attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        return ""

    def _fallback_attack_analysis(self, crawl_data: list) -> list:
        """Fallback attack surface analysis when AI fails"""
        # Simple pattern-based fallback
        high_risk_endpoints = []
        
        for endpoint in crawl_data[:10]:  # Limit to first 10
            if not isinstance(endpoint, dict):
                continue
                
            url = endpoint.get('url', '').lower()
            params = endpoint.get('params', {})
            
            # Simple risk assessment
            risk_score = 0
            if any(kw in url for kw in ['admin', 'login', 'api', 'user']):
                risk_score += 30
            if any(kw in str(params).lower() for kw in ['id', 'password', 'token']):
                risk_score += 40
            
            if risk_score >= 50:
                high_risk_endpoints.append({
                    'url': url,
                    'risk_score': risk_score,
                    'reason': 'Pattern-based detection fallback'
                })
        
        return high_risk_endpoints

    def _fallback_validation_result(self, finding: dict) -> dict:
        """Fallback validation when AI fails"""
        return {
            "valid": True,
            "confidence": 0.6,
            "false_positive_indicators": ["AI validation unavailable"],
            "true_positive_indicators": ["Using fallback validation"],
            "severity_adjustment": "none",
            "adjusted_severity": finding.get('severity', 'Medium'),
            "validation_evidence": "Fallback pattern validation",
            "recommended_actions": ["Manual verification required"]
        }

    def _fallback_exploit_poc(self, finding: dict) -> dict:
        """Fallback exploit PoC when AI fails"""
        vuln_type = finding.get('type', '').lower()
        url = finding.get('url', '')
        payload = finding.get('payload', '')
        
        return {
            "poc_variants": [
                {
                    "method": "curl",
                    "command": f"curl -X GET '{url}?test=payload'",
                    "description": "Basic curl test",
                    "expected_output": "Varies based on vulnerability type",
                    "risk_level": "Low",
                    "safety_warnings": ["Test in controlled environment"]
                }
            ],
            "exploitation_steps": [
                "1. Identify vulnerable parameter",
                "2. Craft appropriate payload",
                "3. Send crafted request",
                "4. Analyze response for success indicators"
            ],
            "verification_checks": [
                "Check for expected response patterns",
                "Verify no system damage occurred",
                "Confirm vulnerability reproduction"
            ]
        }

    # Advanced AI capabilities
    async def generate_attack_scenarios(self, findings: List[Dict]) -> List[Dict]:
        """Generate comprehensive attack scenarios from findings"""
        prompt = f"""
Generate realistic attack scenarios based on these security findings:

FINDINGS:
{json.dumps(findings, indent=2)}

Create 3-5 detailed attack scenarios showing how an attacker could:
1. Chain multiple vulnerabilities together
2. Escalate privileges
3. Access sensitive data
4. Maintain persistence
5. Evade detection

For each scenario, include:
- Initial access vector
- Vulnerability exploitation steps
- Lateral movement techniques
- Data exfiltration methods
- Impact assessment

RETURN JSON format:
{{
  "attack_scenarios": [
    {{
      "title": "string",
      "description": "string",
      "steps": ["string"],
      "vulnerabilities_used": ["string"],
      "impact_level": "Low/Medium/High/Critical",
      "detection_difficulty": "Low/Medium/High",
      "prevention_measures": ["string"]
    }}
  ],
  "overall_risk_assessment": {{
    "business_impact": "string",
    "likelihood": "string",
    "recommended_actions": ["string"]
  }}
}}
"""
        try:
            text = await self._call_ollama_with_retry(prompt)
            return _extract_json(text) or []
        except Exception as e:
            logger.error(f"Attack scenario generation failed: {e}")
            return []

    async def assess_business_impact(self, findings: List[Dict], business_context: Dict = None) -> Dict:
        """Assess business impact of findings"""
        prompt = f"""
Assess business impact for these security findings:

FINDINGS:
{json.dumps(findings, indent=2)}

BUSINESS CONTEXT:
{business_context or 'No specific business context provided'}

Evaluate:
1. Financial impact potential
2. Reputation damage risk
3. Regulatory compliance implications
4. Operational disruption potential
5. Data breach consequences

Provide impact assessment with monetary estimates where possible.

RETURN JSON format:
{{
  "impact_assessment": {{
    "financial_impact": {{
      "estimated_cost": "string",
      "confidence": 0.0,
      "factors": ["string"]
    }},
    "reputation_impact": {{
      "severity": "Low/Medium/High/Critical",
      "recovery_time": "string"
    }},
    "compliance_impact": {{
      "regulations_affected": ["string"],
      "potential_fines": "string"
    }},
    "operational_impact": {{
      "downtime_risk": "string",
      "recovery_complexity": "string"
    }}
  }},
  "risk_prioritization": [
    {{
      "finding_type": "string",
      "business_priority": "string",
      "recommended_timeline": "string"
    }}
  ]
}}
"""
        try:
            text = await self._call_ollama_with_retry(prompt)
            return _extract_json(text) or {}
        except Exception as e:
            logger.error(f"Business impact assessment failed: {e}")
            return {}

# Singleton instance for easy access
ai_brain = AIBrain()

