# scanner/dast/priority_engine.py
#
# ENHANCED PRIORITY ENGINE — Intelligent endpoint prioritization for scan scheduling
# Uses machine learning-like patterns to identify high-value targets

import re
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum

class EndpointCategory(Enum):
    AUTHENTICATION = "authentication"
    ADMINISTRATIVE = "administrative"
    DATA_ACCESS = "data_access"
    FILE_OPERATIONS = "file_operations"
    BUSINESS_CRITICAL = "business_critical"
    API_ENDPOINT = "api_endpoint"
    SEARCH_FUNCTION = "search_function"
    GENERIC = "generic"

class PriorityEngine:
    def __init__(self, config: Optional[Dict] = None):
        self.config = {
            "high_risk_keywords": {
                "admin", "login", "auth", "account", "api", "checkout", 
                "user", "password", "upload", "file", "payment", "token",
                "session", "database", "config", "setting", "credential",
                "oauth", "jwt", "sso", "mfa", "2fa", "reset", "recovery"
            },
            "medium_risk_keywords": {
                "search", "query", "filter", "find", "id", "view", "page",
                "list", "get", "post", "put", "delete", "update", "create",
                "edit", "modify", "export", "import", "download", "report"
            },
            "category_patterns": {
                EndpointCategory.AUTHENTICATION: {
                    "login", "auth", "authenticate", "signin", "signup",
                    "register", "password", "credential", "token", "session",
                    "oauth", "jwt", "sso", "mfa", "2fa"
                },
                EndpointCategory.ADMINISTRATIVE: {
                    "admin", "administrator", "manage", "management",
                    "config", "setting", "configuration", "system",
                    "control", "dashboard", "console", "superuser"
                },
                EndpointCategory.DATA_ACCESS: {
                    "database", "db", "sql", "query", "data", "record",
                    "user", "customer", "account", "profile", "information"
                },
                EndpointCategory.FILE_OPERATIONS: {
                    "upload", "download", "file", "document", "attachment",
                    "image", "media", "resource", "asset", "storage"
                },
                EndpointCategory.BUSINESS_CRITICAL: {
                    "payment", "checkout", "purchase", "buy", "cart",
                    "order", "invoice", "transaction", "billing",
                    "financial", "credit", "card", "bank", "transfer"
                },
                EndpointCategory.API_ENDPOINT: {
                    "api", "rest", "graphql", "json", "xml", "endpoint",
                    "v1", "v2", "v3", "resource", "service", "rpc"
                },
                EndpointCategory.SEARCH_FUNCTION: {
                    "search", "query", "find", "filter", "lookup",
                    "discover", "explore", "browse", "results"
                }
            },
            "score_weights": {
                EndpointCategory.AUTHENTICATION: 15,
                EndpointCategory.ADMINISTRATIVE: 14,
                EndpointCategory.BUSINESS_CRITICAL: 13,
                EndpointCategory.DATA_ACCESS: 12,
                EndpointCategory.FILE_OPERATIONS: 11,
                EndpointCategory.API_ENDPOINT: 10,
                EndpointCategory.SEARCH_FUNCTION: 8,
                EndpointCategory.GENERIC: 5
            },
            "parameter_boost": {
                "id": 3, "user": 3, "account": 3, "file": 3, "path": 3,
                "token": 4, "password": 4, "key": 4, "secret": 4,
                "redirect": 2, "url": 2, "callback": 2,
                "query": 2, "search": 2, "filter": 2
            },
            "method_weights": {
                "POST": 3, "PUT": 3, "DELETE": 4, "PATCH": 3,
                "GET": 1, "HEAD": 1, "OPTIONS": 1
            }
        }
        
        if config:
            self.config.update(config)

    def categorize_endpoint(self, url: str, method: str = "GET") -> EndpointCategory:
        """
        Categorize endpoint based on URL patterns and HTTP method.
        
        Args:
            url: The endpoint URL
            method: HTTP method
            
        Returns:
            Endpoint category
        """
        url_lower = url.lower()
        
        for category, patterns in self.config["category_patterns"].items():
            if any(pattern in url_lower for pattern in patterns):
                return category
                
        return EndpointCategory.GENERIC

    def score_endpoint(self, url: str, method: str = "GET", 
                      params: Optional[List[str]] = None) -> Tuple[int, EndpointCategory]:
        """
        Calculate comprehensive endpoint priority score.
        
        Args:
            url: The endpoint URL
            method: HTTP method
            params: List of parameters (optional)
            
        Returns:
            Tuple of (score, category)
        """
        category = self.categorize_endpoint(url, method)
        base_score = self.config["score_weights"][category]
        
        # Method-based scoring
        method_score = self.config["method_weights"].get(method.upper(), 1)
        base_score *= method_score
        
        # Parameter-based scoring
        if params:
            param_boost = sum(
                self.config["parameter_boost"].get(param.lower(), 1)
                for param in params
            )
            base_score += min(param_boost, 10)  # Cap parameter boost
        
        # URL pattern scoring
        url_lower = url.lower()
        
        # High-risk keywords
        high_risk_matches = sum(
            5 for keyword in self.config["high_risk_keywords"]
            if keyword in url_lower
        )
        
        # Medium-risk keywords
        medium_risk_matches = sum(
            3 for keyword in self.config["medium_risk_keywords"]
            if keyword in url_lower
        )
        
        # Query parameter presence
        query_boost = 4 if "?" in url else 0
        
        # API version pattern
        api_version_boost = 0
        if re.search(r'/api/v\d+/', url_lower):
            api_version_boost = 3
        
        total_score = base_score + high_risk_matches + medium_risk_matches + query_boost + api_version_boost
        
        return min(total_score, 100), category

    def prioritize_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """
        Prioritize endpoints based on comprehensive scoring.
        
        Args:
            endpoints: List of endpoint dictionaries with 'url' and optional 'method', 'params'
            
        Returns:
            Prioritized list of endpoints with scores
        """
        scored_endpoints = []
        
        for endpoint in endpoints:
            url = endpoint.get("url", "")
            method = endpoint.get("method", "GET")
            params = endpoint.get("params", [])
            
            score, category = self.score_endpoint(url, method, params)
            
            scored_endpoints.append({
                **endpoint,
                "priority_score": score,
                "category": category.value,
                "scan_priority": self._get_scan_priority(score)
            })
        
        # Sort by priority score (descending)
        scored_endpoints.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return scored_endpoints

    def _get_scan_priority(self, score: int) -> str:
        """Convert score to priority level."""
        if score >= 80:
            return "immediate"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "background"

    def choose_attack_types(self, url: str, method: str = "GET", 
                          params: Optional[List[str]] = None) -> List[str]:
        """
        Select appropriate attack types based on endpoint characteristics.
        
        Args:
            url: The endpoint URL
            method: HTTP method
            params: List of parameters (optional)
            
        Returns:
            List of recommended attack types
        """
        category = self.categorize_endpoint(url, method)
        url_lower = url.lower()
        attacks = set(["xss"])  # Always test for XSS
        
        # Category-based attacks
        if category == EndpointCategory.AUTHENTICATION:
            attacks.update(["sqli", "auth_bypass", "bruteforce", "session_management"])
        elif category == EndpointCategory.ADMINISTRATIVE:
            attacks.update(["sqli", "lfi", "rce", "idor"])
        elif category == EndpointCategory.DATA_ACCESS:
            attacks.update(["sqli", "nosql", "xxe", "ssrf"])
        elif category == EndpointCategory.FILE_OPERATIONS:
            attacks.update(["lfi", "rfi", "upload_bypass", "path_traversal"])
        elif category == EndpointCategory.BUSINESS_CRITICAL:
            attacks.update(["business_logic", "payment_bypass", "privilege_escalation"])
        elif category == EndpointCategory.API_ENDPOINT:
            attacks.update(["graphql", "api_abuse", "injection", "mass_assignment"])
        elif category == EndpointCategory.SEARCH_FUNCTION:
            attacks.update(["sqli", "xss", "ssti", "open_redirect"])
        
        # Parameter-based attacks
        if params:
            param_names = [p.lower() for p in params]
            if any(p in param_names for p in ["id", "user", "account"]):
                attacks.update(["sqli", "idor"])
            if any(p in param_names for p in ["file", "path", "include"]):
                attacks.update(["lfi", "path_traversal"])
            if any(p in param_names for p in ["url", "redirect", "callback"]):
                attacks.update(["open_redirect", "ssrf"])
            if any(p in param_names for p in ["query", "search", "filter"]):
                attacks.update(["sqli", "xss", "ssti"])
        
        # Method-based attacks
        if method.upper() in ["POST", "PUT", "PATCH"]:
            attacks.update(["csrf", "mass_assignment"])
        if method.upper() == "DELETE":
            attacks.update(["http_method_override"])
        
        return sorted(attacks)

    def generate_scan_plan(self, endpoints: List[Dict]) -> Dict:
        """
        Generate optimized scan plan based on endpoint priorities.
        
        Args:
            endpoints: List of endpoints to scan
            
        Returns:
            Structured scan plan
        """
        prioritized = self.prioritize_endpoints(endpoints)
        
        return {
            "immediate_scan": [ep for ep in prioritized if ep["scan_priority"] == "immediate"],
            "high_priority": [ep for ep in prioritized if ep["scan_priority"] == "high"],
            "medium_priority": [ep for ep in prioritized if ep["scan_priority"] == "medium"],
            "low_priority": [ep for ep in prioritized if ep["scan_priority"] == "low"],
            "background_scan": [ep for ep in prioritized if ep["scan_priority"] == "background"],
            "summary": {
                "total_endpoints": len(endpoints),
                "immediate_count": len([ep for ep in prioritized if ep["scan_priority"] == "immediate"]),
                "high_count": len([ep for ep in prioritized if ep["scan_priority"] == "high"]),
                "estimated_scan_time": self._estimate_scan_time(prioritized)
            }
        }

    def _estimate_scan_time(self, endpoints: List[Dict]) -> str:
        """Estimate total scan time based on endpoint priorities."""
        time_estimates = {
            "immediate": 5,  # minutes per endpoint
            "high": 3,
            "medium": 2,
            "low": 1,
            "background": 0.5
        }
        
        total_minutes = sum(
            time_estimates[ep["scan_priority"]] for ep in endpoints
        )
        
        if total_minutes < 60:
            return f"{total_minutes} minutes"
        else:
            hours = total_minutes // 60
            minutes = total_minutes % 60
            return f"{hours}h {minutes}m"

# Legacy compatibility functions
def score_endpoint(url: str) -> int:
    """Legacy function for backward compatibility."""
    engine = PriorityEngine()
    score, _ = engine.score_endpoint(url)
    return score

def prioritize(endpoints: list) -> list:
    """Legacy function for backward compatibility."""
    engine = PriorityEngine()
    endpoint_dicts = [{"url": ep} for ep in endpoints]
    prioritized = engine.prioritize_endpoints(endpoint_dicts)
    return [ep["url"] for ep in prioritized]

def choose_attacks(url: str) -> list:
    """Legacy function for backward compatibility."""
    engine = PriorityEngine()
    return engine.choose_attack_types(url)
