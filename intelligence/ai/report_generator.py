# intelligence/ai/report_generator.py
# ──────────────────────────────────────────────────────────────────────────────
# ENHANCED REPORT GENERATOR — Local Ollama with comprehensive reporting
# Features: CVE mapping, compliance tracking, risk scoring, multiple formats
# ──────────────────────────────────────────────────────────────────────────────

import json
import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from scanner.ai_brain import _call_ollama, _extract_json

logger = logging.getLogger(__name__)

# Severity weightings for risk scoring
SEVERITY_WEIGHTS = {
    "Critical": 10.0,
    "High": 6.0,
    "Medium": 3.0,
    "Low": 1.0,
    "Info": 0.5
}

# Compliance frameworks mapping
COMPLIANCE_FRAMEWORKS = {
    "OWASP Top 10": {
        "A01:2021-Broken Access Control": ["idor", "access", "authorization"],
        "A03:2021-Injection": ["sqli", "xss", "ssti", "cmdi", "lfi"],
        "A05:2021-Security Misconfiguration": ["headers", "cors", "config"],
        "A06:2021-Vulnerable Components": ["version", "library", "framework"]
    },
    "NIST CSF": {
        "Identify": ["discovery", "inventory", "assessment"],
        "Protect": ["authentication", "access", "encryption"],
        "Detect": ["monitoring", "scanning", "logging"],
        "Respond": ["incident", "response", "containment"],
        "Recover": ["backup", "recovery", "restoration"]
    }
}

class AIReportGenerator:
    """
    Enhanced executive report generator using local Ollama with comprehensive
    risk assessment, compliance mapping, and multiple output formats.
    """

    def __init__(self):
        self.report_cache = {}
        self.max_retries = 3

    async def generate_report(self, data: dict, target: str) -> dict:
        """Generate comprehensive security assessment report"""
        findings = data.get("findings", [])
        
        if not findings:
            return self._empty_report(target)

        try:
            # Process findings in parallel where possible
            enriched_findings = await self._enrich_findings(findings)
            risk_assessment = self._calculate_risk_score(enriched_findings)
            compliance_map = self._map_compliance(enriched_findings)
            
            # Generate AI-powered content
            ai_content = await self._generate_ai_content(
                target, enriched_findings, risk_assessment, compliance_map
            )

            return {
                "metadata": self._generate_metadata(target),
                "executive_summary": ai_content.get("executive_summary", ""),
                "technical_summary": ai_content.get("technical_summary", ""),
                "risk_assessment": risk_assessment,
                "compliance": compliance_map,
                "findings": enriched_findings,
                "remediation_roadmap": ai_content.get("remediation_plan", []),
                "attack_scenarios": ai_content.get("attack_narrative", ""),
                "recommendations": ai_content.get("recommendations", [])
            }

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return self._fallback_report(target, findings)

    async def _enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        """Enrich findings with CVE mapping and additional metadata"""
        enriched = []
        
        for finding in findings:
            enriched_finding = {
                **finding,
                "cve_references": await self._find_cve_references(finding),
                "owasp_category": self._map_owasp_category(finding),
                "business_impact": self._assess_business_impact(finding),
                "remediation_complexity": self._assess_remediation_complexity(finding),
                "evidence_samples": finding.get("evidence", "")[:500],
                "timestamp": datetime.now().isoformat()
            }
            enriched.append(enriched_finding)
        
        return enriched

    async def _find_cve_references(self, finding: Dict) -> List[str]:
        """Find relevant CVE references for a finding"""
        try:
            prompt = f"""
            Analyze this security finding and suggest relevant CVE references:
            
            Type: {finding.get('type', 'Unknown')}
            Evidence: {finding.get('evidence', '')[:200]}
            
            Return only a JSON array of CVE IDs like ["CVE-2021-1234", "CVE-2022-5678"]
            """
            
            response = await _call_ollama(prompt)
            cves = _extract_json(response)
            return cves if isinstance(cves, list) else []
            
        except Exception:
            return []

    def _map_owasp_category(self, finding: Dict) -> str:
        """Map finding to OWASP Top 10 category"""
        finding_type = finding.get("type", "").lower()
        evidence = finding.get("evidence", "").lower()
        
        for category, keywords in COMPLIANCE_FRAMEWORKS["OWASP Top 10"].items():
            if any(keyword in finding_type or keyword in evidence for keyword in keywords):
                return category
        
        return "Other"

    def _assess_business_impact(self, finding: Dict) -> str:
        """Assess business impact of the finding"""
        severity = finding.get("severity", "Medium")
        
        impact_map = {
            "Critical": "High business impact - could lead to system compromise, data breach, or service disruption",
            "High": "Significant business impact - could affect multiple users or systems",
            "Medium": "Moderate business impact - could affect individual users or specific functionality",
            "Low": "Limited business impact - primarily cosmetic or informational",
            "Info": "Minimal business impact - informational only"
        }
        
        return impact_map.get(severity, "Unknown impact")

    def _assess_remediation_complexity(self, finding: Dict) -> str:
        """Assess complexity of remediation"""
        
        finding_type = finding.get("type", "").lower()
        
        if any(t in finding_type for t in ["sqli", "xss", "rce"]):
            return "High complexity - requires code changes and security review"
        elif any(t in finding_type for t in ["config", "headers", "cors"]):
            return "Medium complexity - requires configuration changes"
        else:
            return "Low complexity - can be addressed quickly"

    def _calculate_risk_score(self, findings: List[Dict]) -> Dict:
        """Calculate comprehensive risk score"""
        total_score = 0.0
        max_possible = 0.0
        severity_counts = {level: 0 for level in SEVERITY_WEIGHTS.keys()}
        
        for finding in findings:
            severity = finding.get("severity", "Medium")
            weight = SEVERITY_WEIGHTS.get(severity, 1.0)
            total_score += weight
            max_possible += 10.0  # Max weight for Critical
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        risk_score = min(10.0, (total_score / max_possible * 10)) if max_possible > 0 else 0
        
        return {
            "overall_score": round(risk_score, 1),
            "severity_breakdown": severity_counts,
            "weighted_score": round(total_score, 1),
            "risk_level": self._get_risk_level(risk_score)
        }


    def _get_risk_level(self, score: float) -> str:
        """Convert numeric score to risk level"""
        if score >= 8.0:
            return "Critical"
        elif score >= 6.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 2.0:
            return "Low"
        else:
            return "Info"

    def _map_compliance(self, findings: List[Dict]) -> Dict:
        """Map findings to compliance frameworks"""
        compliance_results = {}
        
        for framework_name, framework_categories in COMPLIANCE_FRAMEWORKS.items():
            framework_results = {}
            for category, keywords in framework_categories.items():
                category_findings = []
                for finding in findings:
                    finding_type = finding.get("type", "").lower()
                    evidence = finding.get("evidence", "").lower()
                    if any(keyword in finding_type or keyword in evidence for keyword in keywords):
                        category_findings.append({
                            "id": finding.get("id", f"{finding.get('type', 'unknown')}_{hash(str(finding))}"),
                            "type": finding.get("type"),
                            "severity": finding.get("severity")
                        })
                
                if category_findings:
                    # Safely get max severity
                    severities = [f["severity"] for f in category_findings if f.get("severity")]
                    max_severity = max(severities, key=lambda x: SEVERITY_WEIGHTS.get(x, 0)) if severities else "None"
                    
                    framework_results[category] = {
                        "findings_count": len(category_findings),
                        "max_severity": max_severity,
                        "findings": category_findings
                    }
            
            if framework_results:
                compliance_results[framework_name] = framework_results
        
        return compliance_results


    async def _generate_ai_content(self, target: str, findings: List[Dict], 
                                 risk_assessment: Dict, compliance_map: Dict) -> Dict:
        """Generate AI-powered report content"""
        compact_findings = [
            {
                "type": f.get("type"),
                "severity": f.get("severity"),
                "owasp_category": f.get("owasp_category"),
                "business_impact": f.get("business_impact"),
                "evidence": f.get("evidence_samples", "")[:150]
            }
            for f in findings
        ]

        prompt = f"""
Act as a Lead Security Consultant. Generate a comprehensive security assessment report for {target}.

RISK ASSESSMENT:
- Overall Score: {risk_assessment.get('overall_score', 0)}/10
- Risk Level: {risk_assessment.get('risk_level', 'Unknown')}
- Severity Breakdown: {json.dumps(risk_assessment.get('severity_breakdown', {}))}

COMPLIANCE FINDINGS:
{json.dumps(compliance_map, indent=2)}

SECURITY FINDINGS (Total: {len(findings)}):
{json.dumps(compact_findings, indent=2)}

Generate a comprehensive report with these sections:

{{
  "executive_summary": "3-4 paragraph executive summary for management",
  "technical_summary": "Detailed technical summary for security team",
  "attack_narrative": "Detailed attack scenario showing how findings could be chained",
  "remediation_plan": [
    {{
      "priority": "Critical",
      "actions": ["Action 1", "Action 2"],
      "timeline": "Immediate",
      "owner": "Security Team"
    }}
  ],
  "recommendations": [
    {{
      "category": "Technical",
      "items": ["Recommendation 1", "Recommendation 2"]
    }},
    {{
      "category": "Process",
      "items": ["Process recommendation 1", "Process recommendation 2"]
    }}
  ]
}}
"""

        for attempt in range(self.max_retries):
            try:
                text = await _call_ollama(prompt)
                ai_content = _extract_json(text)
                
                # Validate the response structure
                if all(key in ai_content for key in ["executive_summary", "technical_summary", 
                                                   "remediation_plan", "recommendations"]):
                    return ai_content
                    
            except Exception as e:
                logger.warning(f"AI content generation attempt {attempt + 1} failed: {e}")
                if attempt == self.max_retries - 1:
                    raise
        
        return self._fallback_ai_content(target, findings)

    def _generate_metadata(self, target: str) -> Dict:
        """Generate report metadata"""
        return {
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "report_version": "2.0",
            "assessment_type": "Automated DAST Scan",
            "tool": "Sentinel Security Scanner"
        }

    def _fallback_ai_content(self, target: str, findings: List[Dict]) -> Dict:
        """Fallback content when AI generation fails"""
        return {
            "executive_summary": f"Security assessment completed for {target}. {len(findings)} findings identified requiring review.",
            "technical_summary": f"Technical analysis revealed {len(findings)} security findings across various categories.",
            "attack_narrative": "Review individual findings for potential attack scenarios.",
            "remediation_plan": [{
                "priority": "Review",
                "actions": ["Review all findings", "Prioritize based on severity"],
                "timeline": "Within 7 days",
                "owner": "Security Team"
            }],
            "recommendations": [{
                "category": "General",
                "items": ["Implement regular security scanning", "Review security headers configuration"]
            }]
        }

    def _fallback_report(self, target: str, findings: List[Dict]) -> Dict:
        """Fallback report when generation fails"""
        risk_score = self._calculate_risk_score(findings)
        
        return {
            "metadata": self._generate_metadata(target),
            "executive_summary": f"Security assessment completed for {target} with {len(findings)} findings.",
            "technical_summary": "Detailed analysis could not be generated due to processing error.",
            "risk_assessment": risk_score,
            "compliance": {},
            "findings": findings,
            "remediation_roadmap": [{
                "priority": "Review",
                "actions": ["Review generated findings", "Contact security team"],
                "timeline": "ASAP",
                "owner": "Security Team"
            }],
            "attack_scenarios": "Unable to generate attack scenarios due to processing error.",
            "recommendations": [{
                "category": "Immediate",
                "items": ["Review the findings list", "Prioritize Critical and High severity issues"]
            }]
        }

    def _empty_report(self, target: str) -> dict:
        """Generate report for no findings"""
        return {
            "metadata": self._generate_metadata(target),
            "executive_summary": "No vulnerabilities were identified during this automated security scan.",
            "technical_summary": "The target application passed all automated security tests without identified vulnerabilities.",
            "risk_assessment": {
                "overall_score": 0,
                "severity_breakdown": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
                "weighted_score": 0,
                "risk_level": "Info"
            },
            "compliance": {},
            "findings": [],
            "remediation_roadmap": [{
                "priority": "Maintenance",
                "actions": ["Continue regular security monitoring", "Maintain current security practices"],
                "timeline": "Ongoing",
                "owner": "Security Team"
            }],
            "attack_scenarios": "No specific attack scenarios identified due to absence of vulnerabilities.",
            "recommendations": [{
                "category": "Preventive",
                "items": ["Continue secure development practices", "Maintain regular security assessments"]
            }]
        }

    # ──────────────────────────────────────────────────────────────────────────
    # OUTPUT FORMATTERS
    # ──────────────────────────────────────────────────────────────────────────

    async def generate_html_report(self, report_data: Dict) -> str:
        """Generate HTML format report - TODO: Implement HTML template rendering"""
        # Placeholder implementation
        return f"<html><body><h1>Security Report</h1><pre>{json.dumps(report_data, indent=2)}</pre></body></html>"

    async def generate_markdown_report(self, report_data: Dict) -> str:
        """Generate Markdown format report - TODO: Implement Markdown template"""
        # Placeholder implementation
        return f"# Security Report\n\n```json\n{json.dumps(report_data, indent=2)}\n```"


    async def generate_json_report(self, report_data: Dict) -> str:
        """Generate JSON format report"""
        return json.dumps(report_data, indent=2, ensure_ascii=False)
