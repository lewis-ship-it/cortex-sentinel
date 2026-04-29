# intelligence/attack_planner.py
# ──────────────────────────────────────────────────────────────────────────────
# ADVANCED ATTACK PLANNER — Sophisticated attack planning with MITRE ATT&CK
# alignment, resource optimization, and adaptive strategy development
# ──────────────────────────────────────────────────────────────────────────────

import random
import logging
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
import math
import re

logger = logging.getLogger(__name__)

# MITRE ATT&CK Technique Mapping
MITRE_TECHNIQUES = {
    "xss": "T1059.007",  # JavaScript
    "sqli": "T1190",     # Exploit Public-Facing Application
    "idor": "T1210",     # Exploitation of Remote Services
    "ssrf": "T1199",     # Trusted Relationship
    "cmdi": "T1203",     # Exploitation for Client Execution
    "ssti": "T1221",     # Template Injection
    "lfi": "T1083",      # File and Directory Discovery
    "xxe": "T1220",      # XEE
    "race_condition": "T1078",  # Valid Accounts
    "mass_assignment": "T1134", # Access Token Manipulation
}

# Resource requirements for different attack types
ATTACK_RESOURCES = {
    "sqli_deep": {"time": 300, "complexity": "high", "stealth": "low"},
    "xss_exploit": {"time": 120, "complexity": "medium", "stealth": "medium"},
    "idor_enum": {"time": 60, "complexity": "low", "stealth": "high"},
    "ssrf_pivot": {"time": 180, "complexity": "high", "stealth": "medium"},
    "lfi_read": {"time": 90, "complexity": "medium", "stealth": "low"},
    "rce_exec": {"time": 240, "complexity": "high", "stealth": "low"},
}

class AttackPlanner:

    def __init__(self):
        self.attack_history = []
        self.resource_budget = {
            "time_remaining": 3600,  # 1 hour in seconds
            "max_requests": 1000,
            "stealth_required": True
        }
        self.target_profile = {}
        self.technique_success_rates = {}

    # ─────────────────────────────────────────────
    # ENHANCED PRIORITIZATION
    # ─────────────────────────────────────────────
    def prioritize(self, findings: List[Dict], context: Dict = None) -> List[Dict]:
        """
        Multi-factor prioritization with business context and risk assessment
        """
        if context is None:
            context = {}
        
        prioritized = []
        
        for finding in findings:
            risk_score = self._calculate_risk_score(finding, context)
            business_impact = self._assess_business_impact(finding, context)
            exploitability = self._assess_exploitability(finding)
            
            priority_score = (risk_score * 0.4 + 
                            business_impact * 0.3 + 
                            exploitability * 0.3)
            
            prioritized.append({
                **finding,
                "priority_score": round(priority_score, 2),
                "risk_score": round(risk_score, 2),
                "business_impact": round(business_impact, 2),
                "exploitability": round(exploitability, 2),
                "mitre_technique": MITRE_TECHNIQUES.get(
                    finding.get("type", "").lower().split()[0], "T1199"
                )
            })
        
        # Sort by priority score (descending)
        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
        
        # Apply resource constraints
        prioritized = self._apply_resource_constraints(prioritized)
        
        return prioritized

    def _calculate_risk_score(self, finding: Dict, context: Dict) -> float:
        """Calculate comprehensive risk score"""
        severity_weights = {
            "Critical": 9.0, "High": 7.0, "Medium": 5.0, 
            "Low": 3.0, "Info": 1.0
        }
        
        base_score = severity_weights.get(finding.get("severity", "Low"), 3.0)
        confidence = finding.get("confidence", 0.5)
        
        # Adjust for confidence
        risk_score = base_score * confidence
        
        # Adjust for asset criticality
        asset_criticality = self._get_asset_criticality(finding.get("url", ""), context)
        risk_score *= asset_criticality
        
        # Adjust for threat intelligence
        threat_intel = self._get_threat_intelligence(finding)
        risk_score *= threat_intel
        
        return min(risk_score, 10.0)

    def _get_asset_criticality(self, url: str, context: Dict) -> float:
        """Determine asset criticality from context"""
        url_lower = url.lower()
        
        # Check context first
        business_units = context.get("business_units", {})
        for unit, keywords in business_units.items():
            if any(keyword in url_lower for keyword in keywords):
                return 1.5  # Business-critical
        
        # Default criticality based on URL patterns
        critical_patterns = ["admin", "api", "database", "payment", "user"]
        if any(pattern in url_lower for pattern in critical_patterns):
            return 1.3
        
        return 1.0

    def _get_threat_intelligence(self, finding: Dict) -> float:
        """Apply threat intelligence factors"""
        vuln_type = finding.get("type", "").lower()
        evidence = finding.get("evidence", "").lower()
        
        # Check for recent CVE mentions
        recent_cves = ["cve-2023", "cve-2024", "log4shell", "spring4shell"]
        if any(cve in evidence for cve in recent_cves):
            return 1.8
        
        # Check for exploit availability
        exploit_indicators = ["exploit", "poc", "metasploit", "weaponized"]
        if any(indicator in evidence for indicator in exploit_indicators):
            return 1.6
        
        return 1.0

    def _assess_business_impact(self, finding: Dict, context: Dict) -> float:
        """Assess business impact of the finding"""
        impact = 5.0  # Base impact
        
        # Adjust based on vulnerability type
        vuln_type = finding.get("type", "").lower()
        if any(t in vuln_type for t in ["sqli", "rce", "ssrf"]):
            impact += 3.0
        elif any(t in vuln_type for t in ["xss", "idor", "lfi"]):
            impact += 2.0
        
        # Adjust based on data sensitivity
        evidence = finding.get("evidence", "").lower()
        sensitive_data = ["password", "credit", "ssn", "token", "key"]
        if any(data in evidence for data in sensitive_data):
            impact += 2.0
        
        return min(impact / 10.0, 1.0)  # Normalize to 0-1

    def _assess_exploitability(self, finding: Dict) -> float:
        """Assess exploitability of the finding"""
        exploitability = 5.0  # Base exploitability
        
        # Adjust based on complexity
        complexity = finding.get("complexity", "medium").lower()
        if complexity == "low":
            exploitability += 3.0
        elif complexity == "high":
            exploitability -= 2.0
        
        # Adjust based on evidence quality
        evidence = finding.get("evidence", "")
        if evidence and len(evidence) > 100:
            exploitability += 2.0
        
        return min(exploitability / 10.0, 1.0)  # Normalize to 0-1

    def _apply_resource_constraints(self, findings: List[Dict]) -> List[Dict]:
        """Apply resource constraints to prioritization"""
        constrained = []
        
        for finding in findings:
            # Check if we have resources for this attack type
            vuln_type = finding.get("type", "").lower()
            resource_req = ATTACK_RESOURCES.get(vuln_type, {})
            
            if self._can_allocate_resources(resource_req):
                constrained.append(finding)
            
            # Stop when we reach resource limits
            if len(constrained) >= 10:  # Maximum 10 prioritized findings
                break
        
        return constrained

    def _can_allocate_resources(self, resource_req: Dict) -> bool:
        """Check if resources can be allocated for this attack"""
        if not resource_req:
            return True
            
        time_needed = resource_req.get("time", 60)
        stealth_req = resource_req.get("stealth", "medium")
        
        # Check time budget
        if time_needed > self.resource_budget["time_remaining"]:
            return False
            
        # Check stealth requirements
        if self.resource_budget["stealth_required"] and stealth_req == "low":
            return False
            
        return True

    # ─────────────────────────────────────────────
    # ADVANCED DECISION ENGINE
    # ─────────────────────────────────────────────
    def decide_next_actions(self, findings: List[Dict], current_state: Dict = None) -> List[Dict]:
        """
        Sophisticated decision engine with state awareness and adaptive planning
        """
        if current_state is None:
            current_state = {
                "compromised_assets": [],
                "access_level": "none",
                "detection_risk": "low"
            }
        
        actions = []
        
        for finding in findings[:20]:  # Consider top 20 findings
            action_plan = self._generate_action_plan(finding, current_state)
            if action_plan:
                actions.extend(action_plan)
        
        # Optimize action sequence
        actions = self._optimize_action_sequence(actions, current_state)
        
        return actions

    def _generate_action_plan(self, finding: Dict, current_state: Dict) -> List[Dict]:
        """Generate comprehensive action plan for a finding"""
        vuln_type = finding.get("type", "").lower()
        url = finding.get("url", "")
        
        action_plans = {
            "xss": self._plan_xss_attack,
            "sqli": self._plan_sqli_attack,
            "idor": self._plan_idor_attack,
            "ssrf": self._plan_ssrf_attack,
            "cmdi": self._plan_cmdi_attack,
            "ssti": self._plan_ssti_attack,
            "lfi": self._plan_lfi_attack,
            "xxe": self._plan_xxe_attack,
            "race_condition": self._plan_race_attack,
            "mass_assignment": self._plan_mass_assignment_attack
        }
        
        planner = action_plans.get(vuln_type.split()[0], self._plan_generic_attack)
        return planner(finding, current_state)

    def _plan_xss_attack(self, finding: Dict, current_state: Dict) -> List[Dict]:
        """Plan XSS attack actions"""
        actions = []
        url = finding.get("url", "")
        
        # Session stealing
        actions.append({
            "action": "steal_session",
            "target": url,
            "technique": "XSS Session Hijacking",
            "mitre_id": "T1059.007",
            "priority": "high",
            "resources": ATTACK_RESOURCES.get("xss_exploit", {}),
            "prerequisites": ["web_access"],
            "expected_outcome": "Session token compromise"
        })
        
        # Keylogging
        actions.append({
            "action": "deploy_keylogger",
            "target": url,
            "technique": "XSS Keylogging",
            "mitre_id": "T1059.007",
            "priority": "medium",
            "resources": ATTACK_RESOURCES.get("xss_exploit", {}),
            "prerequisites": ["web_access"],
            "expected_outcome": "Credential capture"
        })
        
        return actions

    def _plan_sqli_attack(self, finding: Dict, current_state: Dict) -> List[Dict]:
        """Plan SQL injection attack actions"""
        actions = []
        url = finding.get("url", "")
        
        # Data extraction
        actions.append({
            "action": "dump_database",
            "target": url,
            "technique": "SQLi Data Exfiltration",
            "mitre_id": "T1190",
            "priority": "critical",
            "resources": ATTACK_RESOURCES.get("sqli_deep", {}),
            "prerequisites": ["db_access"],
            "expected_outcome": "Database schema and data extraction"
        })
        
        # Authentication bypass
        actions.append({
            "action": "bypass_auth",
            "target": url,
            "technique": "SQLi Authentication Bypass",
            "mitre_id": "T1190",
            "priority": "high",
            "resources": ATTACK_RESOURCES.get("sqli_deep", {}),
            "prerequisites": ["auth_endpoint"],
            "expected_outcome": "Administrative access"
        })
        
        return actions

    def _plan_idor_attack(self, finding: Dict, current_state: Dict) -> List[Dict]:
        """Plan IDOR attack actions"""
        actions = []
        url = finding.get("url", "")
        
        # ID enumeration
        actions.append({
            "action": "enumerate_ids",
            "target": url,
            "technique": "IDOR Enumeration",
            "mitre_id": "T1210",
            "priority": "high",
            "resources": ATTACK_RESOURCES.get("idor_enum", {}),
            "prerequisites": ["base_object_id"],
            "expected_outcome": "Object ID discovery and access"
        })
        
        # Privilege escalation
        actions.append({
            "action": "escalate_privileges",
            "target": url,
            "technique": "IDOR Privilege Escalation",
            "mitre_id": "T1210",
            "priority": "critical",
            "resources": ATTACK_RESOURCES.get("idor_enum", {}),
            "prerequisites": ["low_privilege_access"],
            "expected_outcome": "Elevated system access"
        })
        
        return actions

    def _optimize_action_sequence(self, actions: List[Dict], current_state: Dict) -> List[Dict]:
        """Optimize action sequence for efficiency and stealth"""
        if not actions:
            return []
        
        # Group by target and technique
        action_groups = {}
        for action in actions:
            key = f"{action.get('target')}_{action.get('technique')}"
            if key not in action_groups:
                action_groups[key] = []
            action_groups[key].append(action)
        
        # Select best action from each group
        optimized = []
        for group_actions in action_groups.values():
            # Prioritize by priority and resource efficiency
            best_action = max(group_actions, key=lambda x: (
                self._priority_score(x.get("priority", "medium")),
                -self._resource_cost(x.get("resources", {}))
            ))
            optimized.append(best_action)
        
        # Sort by priority and dependencies
        optimized.sort(key=lambda x: (
            -self._priority_score(x.get("priority", "medium")),
            x.get("prerequisites", [])
        ))
        
        return optimized

    def _priority_score(self, priority: str) -> int:
        """Convert priority to numeric score"""
        priority_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return priority_scores.get(priority.lower(), 2)

    def _resource_cost(self, resources: Dict) -> int:
        """Calculate resource cost score"""
        time_cost = resources.get("time", 60)
        complexity_cost = {"high": 3, "medium": 2, "low": 1}.get(resources.get("complexity", "medium"), 2)
        return time_cost * complexity_cost

    # ─────────────────────────────────────────────
    # INTELLIGENT TASK GENERATION
    # ─────────────────────────────────────────────
    def generate_tasks(self, actions: List[Dict]) -> List[Dict]:
        """Generate optimal tasks from action plans"""
        tasks = []
        
        for action in actions:
            task_generator = {
                "enumerate_ids": self._generate_id_enum_tasks,
                "dump_database": self._generate_sqli_tasks,
                "steal_session": self._generate_xss_tasks,
                "pivot_internal": self._generate_ssrf_tasks,
                "remote_execution": self._generate_rce_tasks
            }.get(action["action"], self._generate_generic_tasks)
            
            tasks.extend(task_generator(action))
        
        return tasks

    def _generate_id_enum_tasks(self, action: Dict) -> List[Dict]:
        """Generate ID enumeration tasks"""
        tasks = []
        base_url = action["target"]
        
        # Smart ID pattern detection
        id_patterns = self._detect_id_patterns(base_url)
        
        for pattern in id_patterns:
            for i in range(1, 6):  # Test first 5 IDs
                test_id = pattern["template"].format(i)
                test_url = base_url.replace(pattern["placeholder"], test_id)
                
                tasks.append({
                    "type": "scan",
                    "technique": "IDOR Enumeration",
                    "url": test_url,
                    "payload": test_id,
                    "expected_pattern": pattern["validation"],
                    "risk_level": "low"
                })
        
        return tasks

    def _detect_id_patterns(self, url: str) -> List[Dict]:
        """Detect ID patterns in URL"""
        patterns = []
        
        # Numeric ID patterns
        if re.search(r'id=\d+', url):
            patterns.append({
                "template": "{}",
                "placeholder": re.search(r'id=\d+', url).group(),
                "validation": "numeric_sequence"
            })
        
        # UUID patterns
        if re.search(r'[0-9a-f]{8}-', url, re.I):
            patterns.append({
                "template": "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "placeholder": re.search(r'[0-9a-f]{8}-', url, re.I).group(),
                "validation": "uuid_format"
            })
        
        return patterns

    def _generate_sqli_tasks(self, action: Dict) -> List[Dict]:
        """Generate SQL injection tasks"""
        return [{
            "type": "exploit",
            "technique": "SQLi Deep Exploitation",
            "url": action["target"],
            "payload_variants": [
                "time_based", "error_based", "boolean_based", "union_based"
            ],
            "expected_indicators": [
                "database_errors", "time_delays", "data_differences"
            ],
            "risk_level": "high"
        }]

    # ─────────────────────────────────────────────
    # FULL PIPELINE WITH ENHANCEMENTS
    # ─────────────────────────────────────────────
    def plan(self, findings: List[Dict], context: Dict = None) -> Dict:
        """
        Complete attack planning pipeline with enhanced capabilities
        """
        if context is None:
            context = {}
        
        # Prioritize findings
        prioritized = self.prioritize(findings, context)
        
        # Decide actions
        actions = self.decide_next_actions(prioritized, context)
        
        # Generate tasks
        tasks = self.generate_tasks(actions)
        
        # Create comprehensive plan
        plan = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_findings": len(findings),
                "prioritized_count": len(prioritized),
                "action_count": len(actions),
                "task_count": len(tasks)
            },
            "prioritized_findings": prioritized,
            "recommended_actions": actions,
            "execution_tasks": tasks,
            "resource_allocation": self._allocate_resources(tasks),
            "timeline_estimation": self._estimate_timeline(tasks),
            "risk_assessment": self._assess_plan_risk(tasks)
        }
        
        return plan

    def _allocate_resources(self, tasks: List[Dict]) -> Dict:
        """Allocate resources for the attack plan"""
        total_time = sum(task.get("time_estimate", 60) for task in tasks)
        total_requests = len(tasks) * 10  # Estimate 10 requests per task
        
        return {
            "time_required": total_time,
            "requests_required": total_requests,
            "stealth_level": "medium",
            "resource_adequacy": total_time <= self.resource_budget["time_remaining"]
        }

    def _estimate_timeline(self, tasks: List[Dict]) -> Dict:
        """Estimate execution timeline"""
        time_estimates = [task.get("time_estimate", 60) for task in tasks]
        
        return {
            "total_duration": sum(time_estimates),
            "parallel_duration": max(time_estimates) if time_estimates else 0,
            "task_breakdown": [
                {
                    "task_type": task.get("type", "unknown"),
                    "duration": task.get("time_estimate", 60),
                    "dependencies": task.get("dependencies", [])
                }
                for task in tasks
            ]
        }

    def _assess_plan_risk(self, tasks: List[Dict]) -> Dict:
        """Assess overall plan risk"""
        risk_scores = [self._task_risk_score(task) for task in tasks]
        
        return {
            "overall_risk": max(risk_scores) if risk_scores else 0,
            "average_risk": sum(risk_scores) / len(risk_scores) if risk_scores else 0,
            "high_risk_tasks": sum(1 for score in risk_scores if score >= 0.7),
            "detection_probability": self._calculate_detection_probability(tasks)
        }

    def _task_risk_score(self, task: Dict) -> float:
        """Calculate risk score for a task"""
        risk_levels = {"critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.3}
        return risk_levels.get(task.get("risk_level", "medium"), 0.5)

    def _calculate_detection_probability(self, tasks: List[Dict]) -> float:
        """Calculate overall detection probability"""
        detection_factors = []
        
        for task in tasks:
            technique = task.get("technique", "")
            stealth = task.get("stealth", "medium")
            
            # Base detection probability
            base_prob = 0.3 if "scan" in task.get("type", "") else 0.6
            
            # Adjust for stealth
            stealth_adjustment = {"high": 0.3, "medium": 0.6, "low": 0.9}.get(stealth, 0.6)
            
            detection_factors.append(base_prob * stealth_adjustment)
        
        return max(detection_factors) if detection_factors else 0.5
