# intelligence/risk_prioritizer.py
# ──────────────────────────────────────────────────────────────────────────────
# ADVANCED RISK PRIORITIZER — Comprehensive risk assessment with CVSS-like
# scoring, business context, and threat intelligence integration
# ──────────────────────────────────────────────────────────────────────────────

import logging
import re
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
import math

logger = logging.getLogger(__name__)

class RiskPrioritizer:

    def __init__(self):
        # Enhanced severity weights with CVSS-like scoring
        self.severity_weights = {
            "Critical": 9.0,
            "High": 7.0,
            "Medium": 5.0,
            "Low": 3.0,
            "Info": 1.0
        }

        # Comprehensive endpoint sensitivity mapping
        self.endpoint_criticality = {
            "admin": 15, "login": 12, "auth": 12, "authenticate": 10,
            "api": 8, "graphql": 8, "rest": 7, "soap": 7,
            "database": 15, "db": 15, "sql": 12,
            "payment": 14, "checkout": 14, "creditcard": 15, "pay": 12,
            "user": 8, "profile": 7, "account": 8,
            "config": 10, "setting": 8, "configuration": 10,
            "upload": 9, "file": 8, "document": 7,
            "email": 8, "mail": 8, "sms": 7,
            "password": 12, "credential": 12, "token": 10,
            "session": 10, "cookie": 8, "jwt": 9,
            "health": 6, "status": 5, "metric": 5,
            "backup": 10, "restore": 10, "export": 8,
            "search": 5, "query": 5, "filter": 4
        }

        # Vulnerability type exploitability factors
        self.exploitability_factors = {
            "sqli": 0.95, "sql injection": 0.95,
            "xss": 0.85, "cross-site scripting": 0.85,
            "rce": 0.98, "remote code execution": 0.98,
            "lfi": 0.80, "local file inclusion": 0.80,
            "rfi": 0.75, "remote file inclusion": 0.75,
            "ssrf": 0.70, "server-side request forgery": 0.70,
            "xxe": 0.65, "xml external entity": 0.65,
            "idor": 0.90, "insecure direct object reference": 0.90,
            "csrf": 0.60, "cross-site request forgery": 0.60,
            "ssti": 0.75, "server-side template injection": 0.75,
            "cors": 0.55, "misconfiguration": 0.50,
            "redirect": 0.65, "open redirect": 0.65,
            "header": 0.45, "security header": 0.45
        }

        # Business impact factors
        self.business_impact_factors = {
            "data_breach": 1.5, "pii": 1.8, "financial": 1.7,
            "authentication": 1.6, "authorization": 1.5,
            "availability": 1.4, "confidentiality": 1.6,
            "integrity": 1.5, "compliance": 1.3
        }

        # Threat intelligence feed (simulated)
        self.threat_intelligence = {
            "cve_2021_44228": {"score_boost": 2.0, "type": "rce", "active": True},
            "log4shell": {"score_boost": 2.0, "type": "rce", "active": True},
            "spring4shell": {"score_boost": 1.8, "type": "rce", "active": True},
            "heartbleed": {"score_boost": 1.5, "type": "memory", "active": False}
        }

    def calculate_endpoint_criticality(self, url: str) -> float:
        """Calculate comprehensive endpoint criticality score"""
        if not url:
            return 5.0  # Default score
        
        url_lower = url.lower()
        score = 5.0  # Base score
        
        # Check for critical keywords
        for keyword, weight in self.endpoint_criticality.items():
            if keyword in url_lower:
                score += weight
        
        # Check for API patterns
        if re.search(r'/api/v\d+/', url_lower):
            score += 8
        if re.search(r'/graphql', url_lower):
            score += 7
        
        # Check for administrative patterns
        if re.search(r'/admin/', url_lower) or re.search(r'/wp-admin/', url_lower):
            score += 12
        
        # Check for financial patterns
        if re.search(r'/payment/', url_lower) or re.search(r'/checkout/', url_lower):
            score += 14
        
        return min(score, 100.0)

    def assess_exploitability(self, vulnerability: Dict) -> float:
        """Assess exploitability based on vulnerability type and context"""
        vuln_type = vulnerability.get("type", "").lower()
        confidence = vulnerability.get("confidence", 0.5)
        
        # Base exploitability from type
        exploitability = self.exploitability_factors.get(vuln_type, 0.5)
        
        # Adjust based on confidence
        exploitability *= confidence
        
        # Adjust based on evidence quality
        evidence = vulnerability.get("evidence", "")
        if evidence and len(evidence) > 50:
            exploitability *= 1.2
        
        # Check for known exploits in threat intelligence
        ti_boost = self._check_threat_intelligence(vulnerability)
        exploitability *= ti_boost
        
        return min(exploitability, 1.0)

    def _check_threat_intelligence(self, vulnerability: Dict) -> float:
        """Check threat intelligence for known exploits"""
        vuln_type = vulnerability.get("type", "").lower()
        evidence = vulnerability.get("evidence", "").lower()
        
        boost = 1.0
        
        # Check for known vulnerability patterns
        for ti_id, ti_data in self.threat_intelligence.items():
            if ti_data["active"] and ti_data["type"] in vuln_type:
                # Additional evidence-based matching
                if ti_id in evidence or any(keyword in evidence for keyword in ti_id.split('_')):
                    boost *= ti_data["score_boost"]
        
        return min(boost, 2.0)  # Cap at 2x boost

    def assess_business_impact(self, vulnerability: Dict) -> float:
        """Assess business impact of the vulnerability"""
        impact = 1.0
        vuln_type = vulnerability.get("type", "").lower()
        evidence = vulnerability.get("evidence", "").lower()
        url = vulnerability.get("url", "").lower()
        
        # Check for data breach potential
        if any(keyword in vuln_type or keyword in evidence for keyword in ["sqli", "injection", "data", "database"]):
            impact *= self.business_impact_factors["data_breach"]
        
        # Check for PII exposure
        if any(keyword in evidence for keyword in ["email", "password", "credit", "card", "ssn", "personal"]):
            impact *= self.business_impact_factors["pii"]
        
        # Check for financial impact
        if any(keyword in url for keyword in ["payment", "checkout", "buy", "purchase", "cart"]):
            impact *= self.business_impact_factors["financial"]
        
        # Check for authentication/authorization issues
        if any(keyword in vuln_type for keyword in ["auth", "session", "cookie", "token", "idor"]):
            impact *= self.business_impact_factors["authentication"]
        
        return min(impact, 2.0)  # Cap at 2x impact

    def calculate_environmental_factors(self, vulnerability: Dict) -> float:
        """Calculate environmental and contextual factors"""
        environmental = 1.0
        url = vulnerability.get("url", "")
        
        # Internet-facing systems have higher risk
        if url and ("://" in url) and not url.startswith(("http://localhost", "http://127.0.0.1", "http://192.168.")):
            environmental *= 1.3
        
        # Check for production environment
        if url and any(env in url for env in ["prod", "production", "live", "www."]):
            environmental *= 1.5
        
        # Check for development/test environments (lower risk)
        if url and any(env in url for env in ["dev", "test", "stage", "staging", "qa"]):
            environmental *= 0.7
        
        return environmental

    def calculate_temporal_factors(self, vulnerability: Dict) -> float:
        """Calculate temporal factors like exploit availability"""
        temporal = 1.0
        evidence = vulnerability.get("evidence", "").lower()
        
        # Check for recent exploit mentions
        recent_keywords = ["recent", "new", "0day", "zero day", "exploit", "poc"]
        if any(keyword in evidence for keyword in recent_keywords):
            temporal *= 1.4
        
        # Check for patch status
        if "patch" in evidence or "fixed" in evidence:
            temporal *= 0.6
        
        return temporal

    def chain_boost(self, vulnerability: Dict, attack_chains: List[List[Dict]]) -> float:
        """Calculate boost for vulnerabilities in attack chains"""
        vuln_id = id(vulnerability)  # Use object id for comparison
        
        for chain in attack_chains:
            # Check if this vulnerability is in any chain
            chain_vuln_ids = [id(vuln) for vuln in chain]
            if vuln_id in chain_vuln_ids:
                # The longer the chain, the more critical this vulnerability
                chain_length = len(chain)
                position = chain_vuln_ids.index(vuln_id)
                
                # Vulnerabilities that enable longer chains get higher boost
                boost = 1.0 + (chain_length * 0.1) + (position * 0.05)
                return min(boost, 2.0)  # Cap at 2x boost
        
        return 1.0

    def calculate_cvss_like_score(self, vulnerability: Dict) -> float:
        """Calculate CVSS-like base score"""
        # Base metrics (simplified)
        attack_vector = 0.85  # Network (assumed)
        attack_complexity = 0.77  # Low (assumed)
        privileges_required = 0.85  # None (assumed)
        user_interaction = 0.85  # None (assumed)
        
        # Impact metrics
        confidentiality_impact = 0.0
        integrity_impact = 0.0
        availability_impact = 0.0
        
        # Set impact based on vulnerability type
        vuln_type = vulnerability.get("type", "").lower()
        if any(t in vuln_type for t in ["sqli", "rce", "lfi", "xxe"]):
            confidentiality_impact = 0.66  # High
            integrity_impact = 0.66  # High
        elif any(t in vuln_type for t in ["xss", "csrf", "idor"]):
            integrity_impact = 0.66  # High
        elif any(t in vuln_type for t in ["ssrf", "redirect"]):
            confidentiality_impact = 0.22  # Low
        
        # Calculate base score
        exploitability = 8.22 * attack_vector * attack_complexity * privileges_required * user_interaction
        impact = 1 - ((1 - confidentiality_impact) * (1 - integrity_impact) * (1 - availability_impact))
        
        if impact <= 0:
            return 0.0
        
        base_score = min((exploitability + impact) * 1.5, 10.0)
        return round(base_score, 1)

    def calculate(self, findings: List[Dict], attack_chains: List[List[Dict]] = None) -> List[Dict]:
        """Calculate comprehensive risk priority scores"""
        if attack_chains is None:
            attack_chains = []
        
        prioritized = []
        
        for finding in findings:
            # Base severity score
            severity = finding.get("severity", "Low")
            base_score = self.severity_weights.get(severity, 3.0) * 10  # Scale to 0-100
            
            # CVSS-like base score
            cvss_score = self.calculate_cvss_like_score(finding) * 10
            
            # Endpoint criticality
            endpoint_score = self.calculate_endpoint_criticality(finding.get("url", ""))
            
            # Exploitability assessment
            exploitability = self.assess_exploitability(finding) * 20
            
            # Business impact
            business_impact = self.assess_business_impact(finding) * 15
            
            # Environmental factors
            environmental = self.calculate_environmental_factors(finding) * 10
            
            # Temporal factors
            temporal = self.calculate_temporal_factors(finding) * 10
            
            # Attack chain boost
            chain_boost = self.chain_boost(finding, attack_chains) * 15
            
            # Confidence factor
            confidence = finding.get("confidence", 0.5) * 10
            
            # Calculate final score with weighted factors
            total_score = (
                base_score * 0.15 +
                cvss_score * 0.20 +
                endpoint_score * 0.15 +
                exploitability * 0.10 +
                business_impact * 0.10 +
                environmental * 0.05 +
                temporal * 0.05 +
                chain_boost * 0.10 +
                confidence * 0.10
            )
            
            # Apply bounds and rounding
            final_score = min(max(round(total_score, 1), 0), 100)
            
            prioritized.append({
                **finding,
                "priority_score": final_score,
                "fix_first": final_score >= 85,
                "risk_factors": {
                    "base_severity": round(base_score, 1),
                    "cvss_score": round(cvss_score, 1),
                    "endpoint_criticality": round(endpoint_score, 1),
                    "exploitability": round(exploitability, 1),
                    "business_impact": round(business_impact, 1),
                    "environmental": round(environmental, 1),
                    "temporal": round(temporal, 1),
                    "chain_boost": round(chain_boost, 1),
                    "confidence": round(confidence, 1)
                },
                "risk_level": self._get_risk_level(final_score)
            })
        
        # Sort by priority score (descending)
        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return prioritized

    def _get_risk_level(self, score: float) -> str:
        """Convert numeric score to risk level"""
        if score >= 90:
            return "Critical"
        elif score >= 75:
            return "High"
        elif score >= 60:
            return "Medium-High"
        elif score >= 45:
            return "Medium"
        elif score >= 30:
            return "Low-Medium"
        elif score >= 15:
            return "Low"
        else:
            return "Informational"

    def prioritize_by_business_unit(self, findings: List[Dict], business_context: Dict) -> List[Dict]:
        """Prioritize findings based on business unit context"""
        prioritized = self.calculate(findings)
        
        # Apply business context adjustments
        for finding in prioritized:
            url = finding.get("url", "").lower()
            business_impact = 1.0
            
            # Adjust based on business unit criticality
            for unit, keywords in business_context.items():
                if any(keyword in url for keyword in keywords):
                    # More critical business units get higher weighting
                    business_impact *= 1.3
                    break
            
            # Apply business impact adjustment
            finding["priority_score"] = min(finding["priority_score"] * business_impact, 100)
            finding["risk_factors"]["business_context"] = round(business_impact, 2)
        
        # Re-sort after business context adjustment
        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
        return prioritized

    def generate_remediation_plan(self, prioritized_findings: List[Dict]) -> Dict:
        """Generate structured remediation plan"""
        critical = [f for f in prioritized_findings if f["priority_score"] >= 85]
        high = [f for f in prioritized_findings if 75 <= f["priority_score"] < 85]
        medium = [f for f in prioritized_findings if 45 <= f["priority_score"] < 75]
        
        return {
            "immediate_action": {
                "timeframe": "Within 24 hours",
                "findings": critical,
                "count": len(critical),
                "total_risk": sum(f["priority_score"] for f in critical)
            },
            "short_term": {
                "timeframe": "Within 7 days",
                "findings": high,
                "count": len(high),
                "total_risk": sum(f["priority_score"] for f in high)
            },
            "medium_term": {
                "timeframe": "Within 30 days",
                "findings": medium,
                "count": len(medium),
                "total_risk": sum(f["priority_score"] for f in medium)
            },
            "long_term": {
                "timeframe": "Next quarter",
                "findings": [f for f in prioritized_findings if f["priority_score"] < 45],
                "count": len(prioritized_findings) - len(critical + high + medium),
                "total_risk": sum(f["priority_score"] for f in prioritized_findings if f["priority_score"] < 45)
            }
        }

