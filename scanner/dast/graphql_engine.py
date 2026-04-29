# scanner/dast/graphql_engine.py
#
# ENHANCED GRAPHQL ENGINE — Comprehensive GraphQL security testing
# Tests: Introspection, batching, DoS, injection, info leakage, misconfigurations

import asyncio
import logging
import json
import re
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin, urlparse
import httpx

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    "graphql_paths": [
        "/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/query",
        "/gql", "/graphql-api", "/api/gql", "/v1/query", "/graphql/query",
        "/api/v1/graphql", "/api/v2/graphql", "/graphql/v1", "/graphql/v2",
    ],
    "timeout": 15,
    "max_depth": 10,
    "batch_size": 50,
    "concurrent_requests": 3,
    "test_introspection": True,
    "test_batching": True,
    "test_dos": True,
    "test_csrf": True,
}

# GraphQL introspection query
GRAPHQL_INTROSPECTION_QUERY = {
    "query": """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args { name type { name kind ofType { name kind } } defaultValue }
        type { name kind ofType { name kind } }
        isDeprecated
        deprecationReason
      }
      inputFields { name type { name kind ofType { name kind } } defaultValue }
      interfaces { name kind }
      enumValues(includeDeprecated: true) { name description isDeprecated }
      possibleTypes { name kind }
    }
    directives {
      name
      description
      locations
      args { name type { name kind ofType { name kind } } defaultValue }
    }
  }
}
"""
}

# GraphQL batching payload
GRAPHQL_BATCH_PAYLOAD = [
    {"query": "query { __typename }"},
    {"query": "query { __typename }"},
    {"query": "query { __typename }"},
]

# Deep query for DoS testing
def generate_deep_query(depth: int) -> str:
    """Generate a deeply nested GraphQL query"""
    query = "query {"
    for i in range(depth):
        query += f"a{i} {{ __typename "
    query += "__typename " + "}" * depth + "}"
    return query

# Field duplication payload
def generate_field_duplication(count: int) -> str:
    """Generate query with duplicated fields"""
    fields = " ".join([f"field{i}: __typename" for i in range(count)])
    return f"query {{ {fields} }}"

class GraphQLEngine:
    def __init__(self, config: Optional[Dict] = None):
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.rate_limiter = asyncio.Semaphore(self.config["concurrent_requests"])

    async def scan(self, client: httpx.AsyncClient, base_url: str) -> List[Dict]:
        """Comprehensive GraphQL security scan"""
        findings = []
        
        try:
            # Discover GraphQL endpoints
            endpoints = await self._discover_graphql_endpoints(client, base_url)
            
            if not endpoints:
                return findings
                
            # Test each discovered endpoint
            for endpoint in endpoints:
                endpoint_findings = await self._test_graphql_endpoint(client, endpoint)
                findings.extend(endpoint_findings)
                
        except Exception as e:
            logger.error(f"GraphQL scan failed for {base_url}: {e}")
            
        return findings

    async def _discover_graphql_endpoints(self, client: httpx.AsyncClient, base_url: str) -> List[str]:
        """Discover GraphQL endpoints using multiple techniques"""
        endpoints = set()
        
        # Test known paths
        for path in self.config["graphql_paths"]:
            endpoint = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            if await self._is_graphql_endpoint(client, endpoint):
                endpoints.add(endpoint)
                
        # Test common variations
        common_variations = [
            "/api" + path for path in self.config["graphql_paths"]
        ] + [
            "/v1" + path for path in self.config["graphql_paths"]
        ]
        
        for path in common_variations:
            endpoint = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            if await self._is_graphql_endpoint(client, endpoint):
                endpoints.add(endpoint)
                
        return list(endpoints)

    async def _is_graphql_endpoint(self, client: httpx.AsyncClient, url: str) -> bool:
        """Check if URL is a GraphQL endpoint"""
        try:
            # Try GET request first
            get_response = await self._safe_request(client, "GET", url)
            if get_response and self._is_graphql_response(get_response):
                return True
                
            # Try POST with simple query
            post_response = await self._safe_request(
                client, "POST", url,
                json={"query": "query { __typename }"},
                headers={"Content-Type": "application/json"}
            )
            if post_response and self._is_graphql_response(post_response):
                return True
                
        except Exception:
            pass
            
        return False

    def _is_graphql_response(self, response: httpx.Response) -> bool:
        """Check if response indicates GraphQL endpoint"""
        if response.status_code not in (200, 400):
            return False
            
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            return False
            
        try:
            data = response.json()
            # GraphQL responses typically have "data" or "errors" keys
            return "data" in data or "errors" in data
        except (json.JSONDecodeError, ValueError):
            return False

    async def _test_graphql_endpoint(self, client: httpx.AsyncClient, endpoint: str) -> List[Dict]:
        """Comprehensive GraphQL endpoint testing"""
        findings = []
        
        # Test introspection
        if self.config["test_introspection"]:
            introspection_finding = await self._test_introspection(client, endpoint)
            if introspection_finding:
                findings.append(introspection_finding)
                
        # Test batching
        if self.config["test_batching"]:
            batching_finding = await self._test_batching(client, endpoint)
            if batching_finding:
                findings.append(batching_finding)
                
        # Test DoS vulnerabilities
        if self.config["test_dos"]:
            dos_findings = await self._test_dos(client, endpoint)
            findings.extend(dos_findings)
            
        # Test CSRF protection
        if self.config["test_csrf"]:
            csrf_finding = await self._test_csrf(client, endpoint)
            if csrf_finding:
                findings.append(csrf_finding)
                
        # Test information disclosure
        info_finding = await self._test_info_disclosure(client, endpoint)
        if info_finding:
            findings.append(info_finding)
            
        return findings

    async def _test_introspection(self, client: httpx.AsyncClient, endpoint: str) -> Optional[Dict]:
        """Test GraphQL introspection"""
        try:
            response = await self._safe_request(
                client, "POST", endpoint,
                json=GRAPHQL_INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
                timeout=self.config["timeout"]
            )
            
            if not response or response.status_code != 200:
                return None
                
            try:
                data = response.json()
            except (json.JSONDecodeError, ValueError):
                return None
                
            if "data" in data and "__schema" in data.get("data", {}):
                schema_data = data["data"]["__schema"]
                return self._report_introspection(endpoint, schema_data)
                
        except Exception as e:
            logger.debug(f"Introspection test failed for {endpoint}: {e}")
            
        return None

    def _report_introspection(self, endpoint: str, schema_data: Dict) -> Dict:
        """Report introspection finding"""
        # Count types and fields for evidence
        type_count = len(schema_data.get("types", []))
        query_type = schema_data.get("queryType", {}).get("name", "Unknown")
        mutation_type = schema_data.get("mutationType", {}).get("name", "None")
        
        return {
            "type": "GraphQL Introspection Enabled",
            "severity": "High",
            "confidence": 0.95,
            "url": endpoint,
            "evidence": f"Schema with {type_count} types, Query: {query_type}, Mutation: {mutation_type}",
            "description": (
                "GraphQL introspection is enabled, allowing attackers to discover "
                "the complete schema structure. This exposes all queries, mutations, "
                "types, and fields, significantly reducing the effort required for "
                "further attacks."
            ),
            "recommendation": (
                "Disable introspection in production environments. Use graphql-disable-introspection "
                "middleware or implement authentication/authorization for introspection queries."
            )
        }

    async def _test_batching(self, client: httpx.AsyncClient, endpoint: str) -> Optional[Dict]:
        """Test GraphQL query batching"""
        try:
            response = await self._safe_request(
                client, "POST", endpoint,
                json=GRAPHQL_BATCH_PAYLOAD,
                headers={"Content-Type": "application/json"},
                timeout=self.config["timeout"]
            )
            
            if not response or response.status_code != 200:
                return None
                
            try:
                data = response.json()
                # Check if response is an array (indicating batching support)
                if isinstance(data, list) and len(data) == len(GRAPHQL_BATCH_PAYLOAD):
                    return self._report_batching(endpoint, data)
                    
            except (json.JSONDecodeError, ValueError):
                pass
                
        except Exception as e:
            logger.debug(f"Batching test failed for {endpoint}: {e}")
            
        return None

    def _report_batching(self, endpoint: str, batch_response: List) -> Dict:
        """Report batching finding"""
        return {
            "type": "GraphQL Batching Enabled",
            "severity": "Medium",
            "confidence": 0.90,
            "url": endpoint,
            "evidence": f"Batch of {len(batch_response)} queries executed successfully",
            "description": (
                "GraphQL query batching is enabled, allowing multiple queries in a single request. "
                "This can be abused to bypass rate limiting, perform denial of service attacks, "
                "or execute multiple operations with a single authentication token."
            ),
            "recommendation": (
                "Implement query whitelisting, depth limiting, or disable batching. "
                "Consider using persisted queries or query cost analysis."
            )
        }

    async def _test_dos(self, client: httpx.AsyncClient, endpoint: str) -> List[Dict]:
        """Test GraphQL DoS vulnerabilities"""
        findings = []
        
        # Test deep queries
        deep_query = generate_deep_query(self.config["max_depth"])
        deep_response = await self._safe_request(
            client, "POST", endpoint,
            json={"query": deep_query},
            headers={"Content-Type": "application/json"},
            timeout=self.config["timeout"]
        )
        
        if deep_response and deep_response.status_code == 200:
            findings.append(self._report_dos(endpoint, "Deep Query", self.config["max_depth"]))
            
        # Test field duplication
        field_query = generate_field_duplication(self.config["batch_size"])
        field_response = await self._safe_request(
            client, "POST", endpoint,
            json={"query": field_query},
            headers={"Content-Type": "application/json"},
            timeout=self.config["timeout"]
        )
        
        if field_response and field_response.status_code == 200:
            findings.append(self._report_dos(endpoint, "Field Duplication", self.config["batch_size"]))
            
        return findings

    def _report_dos(self, endpoint: str, attack_type: str, value: int) -> Dict:
        """Report DoS finding"""
        return {
            "type": "GraphQL DoS Vulnerability",
            "subtype": attack_type,
            "severity": "High",
            "confidence": 0.85,
            "url": endpoint,
            "evidence": f"{attack_type} with {value} elements accepted",
            "description": (
                f"GraphQL endpoint is vulnerable to {attack_type.lower()} attacks. "
                "Attackers can craft expensive queries that consume excessive server "
                "resources, leading to denial of service."
            ),
            "recommendation": (
                "Implement query depth limiting, query cost analysis, and query whitelisting. "
                "Set reasonable timeouts and consider using persisted queries."
            )
        }

    async def _test_csrf(self, client: httpx.AsyncClient, endpoint: str) -> Optional[Dict]:
        """Test CSRF protection on GraphQL endpoint"""
        try:
            # Test without CSRF tokens
            response = await self._safe_request(
                client, "POST", endpoint,
                json={"query": "query { __typename }"},
                headers={"Content-Type": "application/json"},
                timeout=self.config["timeout"]
            )
            
            if response and response.status_code == 200:
                # Check if CSRF protection might be missing
                if not self._has_csrf_protection(response):
                    return self._report_csrf(endpoint)
                    
        except Exception as e:
            logger.debug(f"CSRF test failed for {endpoint}: {e}")
            
        return None

    def _has_csrf_protection(self, response: httpx.Response) -> bool:
        """Check if response indicates CSRF protection"""
        # Check for CSRF-related headers or cookies
        headers = response.headers
        if any(header.lower() in headers for header in ["x-csrf-token", "csrf-token", "x-xsrf-token"]):
            return True
            
        # Check for CSRF tokens in set-cookie
        set_cookie = headers.get("set-cookie", "").lower()
        if "csrf" in set_cookie or "xsrf" in set_cookie:
            return True
            
        return False

    def _report_csrf(self, endpoint: str) -> Dict:
        """Report CSRF finding"""
        return {
            "type": "GraphQL CSRF Vulnerability",
            "severity": "Medium",
            "confidence": 0.75,
            "url": endpoint,
            "evidence": "No CSRF protection headers detected",
            "description": (
                "GraphQL endpoint may be vulnerable to CSRF attacks. "
                "Without proper CSRF protection, attackers can trick authenticated "
                "users into executing arbitrary GraphQL operations."
            ),
            "recommendation": (
                "Implement CSRF tokens, same-site cookies, or require authentication "
                "for all GraphQL operations. Consider using double-submit cookie pattern."
            )
        }

    async def _test_info_disclosure(self, client: httpx.AsyncClient, endpoint: str) -> Optional[Dict]:
        """Test for information disclosure in error messages"""
        try:
            # Send malformed query to trigger errors
            response = await self._safe_request(
                client, "POST", endpoint,
                json={"query": "query { invalidField }"},
                headers={"Content-Type": "application/json"},
                timeout=self.config["timeout"]
            )
            
            if response and response.status_code == 400:
                try:
                    data = response.json()
                    if "errors" in data and self._has_sensitive_info(data["errors"]):
                        return self._report_info_disclosure(endpoint, data["errors"])
                except (json.JSONDecodeError, ValueError):
                    pass
                    
        except Exception as e:
            logger.debug(f"Info disclosure test failed for {endpoint}: {e}")
            
        return None

    def _has_sensitive_info(self, errors: List[Dict]) -> bool:
        """Check if error messages contain sensitive information"""
        sensitive_patterns = [
            r"stack trace", r"at line", r"file://", r"path/to",
            r"database", r"sql", r"query", r"mongo", r"redis",
            r"password", r"secret", r"key", r"token",
        ]
        
        for error in errors:
            message = str(error).lower()
            if any(re.search(pattern, message) for pattern in sensitive_patterns):
                return True
                
        return False

    def _report_info_disclosure(self, endpoint: str, errors: List[Dict]) -> Dict:
        """Report information disclosure finding"""
        error_sample = str(errors[0])[:200] if errors else "No details"
        return {
            "type": "GraphQL Information Disclosure",
            "severity": "Medium",
            "confidence": 0.80,
            "url": endpoint,
            "evidence": f"Error message: {error_sample}...",
            "description": (
                "GraphQL endpoint discloses sensitive information in error messages. "
                "This can reveal internal implementation details, stack traces, or "
                "other information useful to attackers."
            ),
            "recommendation": (
                "Configure GraphQL to return generic error messages in production. "
                "Avoid exposing stack traces, file paths, or database information."
            )
        }

    async def _safe_request(self, client: httpx.AsyncClient, method: str, url: str, 
                          **kwargs) -> Optional[httpx.Response]:
        """Make a safe HTTP request with timeout and error handling"""
        try:
            kwargs.setdefault("timeout", self.config["timeout"])
            return await client.request(method, url, **kwargs)
        except Exception as e:
            logger.debug(f"Request failed: {method} {url}: {e}")
            return None

# Backward compatibility function
async def check_graphql_introspection(client, base_url: str) -> Optional[Dict]:
    """Legacy function for backward compatibility"""
    engine = GraphQLEngine()
    endpoints = await engine._discover_graphql_endpoints(client, base_url)
    
    for endpoint in endpoints:
        finding = await engine._test_introspection(client, endpoint)
        if finding:
            return finding
            
    return None
