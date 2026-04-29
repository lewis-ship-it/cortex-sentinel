# scanner/api_engine.py

import asyncio
import httpx
import json
import logging
import base64
import re
import sys
from urllib.parse import urljoin, urlparse, urlencode
from typing import Dict, List, Set, Optional, Any

# Configure structured logging
logger = logging.getLogger("api_scanner")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# ─────────────────────────────────────────────────────────────
# KNOWN GRAPHQL INTROSPECTION QUERY
# ─────────────────────────────────────────────────────────────
GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind } }
        type { name kind }
      }
    }
  }
}
"""

# ─────────────────────────────────────────────────────────────
# COMMON API PATHS TO PROBE
# ─────────────────────────────────────────────────────────────
COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/graphql",
    "/graphiql",
    "/playground",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/docs",
    "/redoc",
    "/v1",
    "/v2",
    "/health",
    "/metrics",
    "/admin/api",
    "/internal/api",
    "/.well-known/openid-configuration",
]

# ─────────────────────────────────────────────────────────────
# SENSITIVE FIELDS TO CHECK IN RESPONSES
# ─────────────────────────────────────────────────────────────
SENSITIVE_FIELDS = [
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "apikey", "auth", "ssn", "credit_card",
    "card_number", "cvv", "private_key", "access_token",
    "refresh_token", "session", "cookie"
]

# ─────────────────────────────────────────────────────────────
# JWT WEAK SECRETS TO TEST
# ─────────────────────────────────────────────────────────────
WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin",
    "test", "key", "jwt", "token", "changeme", ""
]

# ─────────────────────────────────────────────────────────────
# HTTP METHODS TO TEST ON EACH ENDPOINT
# ─────────────────────────────────────────────────────────────
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


class APIEngine:

    def __init__(self, timeout=10, max_concurrent=20):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.client_limits = httpx.Limits(
            max_connections=max_concurrent,
            max_keepalive_connections=10
        )

    # ─────────────────────────────────────────
    # MAIN ENTRY POINT
    # ─────────────────────────────────────────
    async def scan(self, base_url, auth_token=None, spec_url=None):
        """
        Full API security scan pipeline.

        base_url   : root URL of the API (e.g. https://api.example.com)
        auth_token : optional Bearer token for authenticated testing
        spec_url   : optional OpenAPI/Swagger spec URL to import endpoints

        Returns list of finding dicts compatible with
        AIReportGenerator / RiskPrioritizer.
        """
        findings = []
        headers = self._build_headers(auth_token)

        logger.info(f"Starting API scan: {base_url}")

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=True,  # Enabled SSL verification for security
                follow_redirects=True,
                headers=headers,
                limits=self.client_limits
            ) as client:

                # Health check before proceeding
                if not await self._health_check(client, base_url):
                    findings.append(self._finding(
                        ftype="Target Unreachable",
                        severity="Low",
                        url=base_url,
                        desc="Target did not respond to basic health check",
                        evidence="HTTP request failed or timed out"
                    ))
                    return findings

                # ── 1. Endpoint discovery ─────────────────
                endpoints = await self._discover_endpoints(client, base_url, spec_url)
                logger.info(f"Discovered {len(endpoints)} endpoints")

                # ── 2. GraphQL checks ─────────────────────
                gql_findings = await self._test_graphql(client, base_url)
                findings.extend(gql_findings)

                # ── 3. JWT analysis ───────────────────────
                jwt_findings = await self._test_jwt(client, base_url, auth_token)
                findings.extend(jwt_findings)

                # ── 4. Auth & access control ──────────────
                auth_findings = await self._test_auth(client, base_url, endpoints)
                findings.extend(auth_findings)

                # ── 5. BOLA / IDOR ────────────────────────
                bola_findings = await self._test_bola(client, endpoints)
                findings.extend(bola_findings)

                # ── 6. Rate limiting ──────────────────────
                rate_findings = await self._test_rate_limiting(client, base_url, endpoints)
                findings.extend(rate_findings)

                # ── 7. HTTP method abuse ──────────────────
                method_findings = await self._test_http_methods(client, endpoints)
                findings.extend(method_findings)

                # ── 8. Sensitive data in responses ────────
                leak_findings = await self._test_data_exposure(client, endpoints)
                findings.extend(leak_findings)

                # ── 9. Security headers ───────────────────
                header_findings = await self._test_security_headers(client, base_url)
                findings.extend(header_findings)

                # ── 10. Mass assignment ───────────────────
                mass_findings = await self._test_mass_assignment(client, endpoints)
                findings.extend(mass_findings)

        except httpx.RequestError as e:
            logger.error(f"Network request failed: {e}")
            findings.append(self._finding(
                ftype="Network Error",
                severity="Low",
                url=base_url,
                desc=f"Network request failed: {e}",
                evidence="Request exception occurred"
            ))
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            findings.append(self._finding(
                ftype="Scan Error",
                severity="Low",
                url=base_url,
                desc=f"Unexpected error occurred during scan: {e}",
                evidence="Exception during scanning process"
            ))

        # Deduplicate findings before returning
        findings = self._deduplicate_findings(findings)
        logger.info(f"Scan complete. Found {len(findings)} unique findings.")
        return findings

    async def _health_check(self, client, base_url):
        """Check if the target is responsive before full scan."""
        try:
            response = await client.get(base_url, timeout=5)
            return response.status_code < 500
        except (httpx.RequestError, httpx.TimeoutException):
            return False

    def _deduplicate_findings(self, findings):
        """Remove duplicate findings based on type and URL."""
        seen = set()
        unique_findings = []
        
        for finding in findings:
            key = (finding["type"], finding["url"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings

    # ─────────────────────────────────────────
    # 1. ENDPOINT DISCOVERY (ORIGINAL)
    # ─────────────────────────────────────────
    async def _discover_endpoints(self, client, base_url, spec_url=None):
        """
        Discovers API endpoints via:
        - OpenAPI/Swagger spec (if provided or auto-detected)
        - Common path probing
        """
        endpoints = set()

        # Try to load from spec first
        spec = await self._fetch_spec(client, base_url, spec_url)
        if spec:
            endpoints.update(self._parse_openapi_spec(spec, base_url))
            logger.info(f"Loaded {len(endpoints)} endpoints from spec")

        # Probe common paths regardless
        tasks = [
            self._probe_path(client, base_url, path)
            for path in COMMON_API_PATHS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for path, alive in zip(COMMON_API_PATHS, results):
            if isinstance(alive, bool) and alive:
                endpoints.add(urljoin(base_url, path))

        return list(endpoints)

    async def _fetch_spec(self, client, base_url, spec_url=None):
        """Try known spec URLs and return parsed JSON if found."""
        candidates = [spec_url] if spec_url else []
        candidates += [
            urljoin(base_url, "/openapi.json"),
            urljoin(base_url, "/swagger.json"),
            urljoin(base_url, "/api-docs"),
            urljoin(base_url, "/v1/openapi.json"),
        ]

        for url in candidates:
            if not url:
                continue
            try:
                res = await client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    if "paths" in data or "openapi" in data or "swagger" in data:
                        logger.info(f"Found spec at {url}")
                        return data
            except (httpx.RequestError, json.JSONDecodeError):
                continue
        return None

    def _parse_openapi_spec(self, spec, base_url):
        """Extract all endpoint URLs from an OpenAPI spec."""
        endpoints = set()
        servers = spec.get("servers", [{"url": base_url}])
        base = servers[0].get("url", base_url) if servers else base_url

        for path in spec.get("paths", {}).keys():
            endpoints.add(urljoin(base, path))

        return endpoints

    async def _probe_path(self, client, base_url, path):
        """Return True if path exists (non-404)."""
        async with self.semaphore:
            try:
                url = urljoin(base_url, path)
                res = await client.get(url)
                return res.status_code not in (404, 410)
            except (httpx.RequestError, httpx.TimeoutException):
                return False

    # ─────────────────────────────────────────
    # 2. GRAPHQL CHECKS (ORIGINAL)
    # ─────────────────────────────────────────
    async def _test_graphql(self, client, base_url):
        findings = []
        gql_paths = ["/graphql", "/graphiql", "/api/graphql", "/playground"]

        for path in gql_paths:
            url = urljoin(base_url, path)
            async with self.semaphore:
                try:
                    # ── Introspection enabled? ────────
                    res = await client.post(
                        url,
                        json={"query": GRAPHQL_INTROSPECTION_QUERY},
                        headers={"Content-Type": "application/json"}
                    )

                    if res.status_code == 200:
                        data = res.json()

                        if "data" in data and "__schema" in str(data):
                            findings.append(self._finding(
                                ftype="GraphQL Introspection Enabled",
                                severity="High",
                                url=url,
                                desc="GraphQL introspection is enabled in production. Attackers "
                                     "can dump your entire schema — all types, queries, mutations, "
                                     "and arguments — without any authentication.",
                                evidence=f"__schema returned {len(str(data))} bytes of schema data"
                            ))

                            # ── Extract sensitive type/field names ──
                            schema_str = str(data).lower()
                            for field in SENSITIVE_FIELDS:
                                if field in schema_str:
                                    findings.append(self._finding(
                                        ftype="GraphQL Sensitive Field Exposed in Schema",
                                        severity="Medium",
                                        url=url,
                                        desc=f"Schema exposes a field named '{field}'. Verify "
                                             f"this field is not accessible without proper auth.",
                                        evidence=f"Field '{field}' found in introspection schema"
                                    ))

                        # ── GraphiQL IDE exposed? ─────
                        text = res.text.lower()
                        if "graphiql" in text or "graphql playground" in text:
                            findings.append(self._finding(
                                ftype="GraphQL IDE Exposed",
                                severity="Medium",
                                url=url,
                                desc="GraphQL IDE (GraphiQL or Playground) is publicly accessible. "
                                     "This gives attackers an interactive query interface.",
                                evidence="GraphiQL/Playground UI detected in response"
                            ))

                    # ── Batch query abuse ─────────────
                    batch_res = await client.post(
                        url,
                        json=[
                            {"query": "{ __typename }"},
                            {"query": "{ __typename }"},
                            {"query": "{ __typename }"},
                        ],
                        headers={"Content-Type": "application/json"}
                    )
                    if batch_res.status_code == 200 and isinstance(batch_res.json(), list):
                        findings.append(self._finding(
                            ftype="GraphQL Batching Enabled",
                            severity="Medium",
                            url=url,
                            desc="GraphQL accepts batched queries. This can be abused to bypass "
                                 "rate limiting by sending many queries in a single request.",
                            evidence="Array of queries accepted and executed"
                        ))

                except (httpx.RequestError, json.JSONDecodeError) as e:
                    logger.debug(f"GraphQL test failed for {url}: {e}")
                    continue

        return findings

    # ─────────────────────────────────────────
    # 3. JWT ANALYSIS (ORIGINAL)
    # ─────────────────────────────────────────
    async def _test_jwt(self, client, base_url, auth_token=None):
        findings = []

        token = auth_token or await self._extract_jwt_from_api(client, base_url)
        if not token:
            return findings

        # Strip "Bearer " prefix if present
        token = token.replace("Bearer ", "").strip()

        parts = token.split(".")
        if len(parts) != 3:
            return findings

        header_b64, payload_b64, signature = parts

        # ── Decode header ────────────────────────
        try:
            header = json.loads(self._b64_decode(header_b64))
        except (json.JSONDecodeError, ValueError):
            return findings

        # ── Algorithm: none attack ────────────────
        if header.get("alg", "").lower() in ("none", ""):
            findings.append(self._finding(
                ftype="JWT Algorithm None Accepted",
                severity="Critical",
                url=base_url,
                desc="JWT uses alg=none, meaning the signature is not verified. "
                     "An attacker can forge any token with arbitrary claims.",
                evidence=f"alg: {header.get('alg')}"
            ))

        # ── Weak algorithm ────────────────────────
        if header.get("alg", "") in ("HS256", "HS384", "HS512"):
            # Try weak secrets
            weak_secret_found = self._crack_jwt_secret(token, WEAK_JWT_SECRETS)
            if weak_secret_found is not None:
                findings.append(self._finding(
                    ftype="JWT Weak Secret",
                    severity="Critical",
                    url=base_url,
                    desc=f"JWT is signed with a weak, guessable secret: '{weak_secret_found}'. "
                         f"Attackers can forge tokens and impersonate any user.",
                    evidence=f"Secret cracked: '{weak_secret_found}'"
                ))

        # ── Sensitive data in payload ─────────────
        try:
            payload = json.loads(self._b64_decode(payload_b64))
            for field in SENSITIVE_FIELDS:
                if field in payload:
                    findings.append(self._finding(
                        ftype="Sensitive Data in JWT Payload",
                        severity="Medium",
                        url=base_url,
                        desc=f"JWT payload contains sensitive field '{field}'. "
                             f"JWT payloads are base64-encoded, not encrypted — anyone "
                             f"with the token can read this data.",
                        evidence=f"Field '{field}' present in decoded payload"
                    ))

            # ── No expiry ─────────────────────────
            if "exp" not in payload:
                findings.append(self._finding(
                    ftype="JWT Missing Expiration",
                    severity="Medium",
                    url=base_url,
                    desc="JWT has no 'exp' (expiration) claim. Stolen tokens are valid forever.",
                    evidence="No 'exp' field in JWT payload"
                ))

        except (json.JSONDecodeError, ValueError):
            pass

        return findings

    async def _extract_jwt_from_api(self, client, base_url):
        """Attempt to get a JWT by hitting common login endpoints."""
        login_paths = ["/api/login", "/api/auth", "/auth/token", "/login", "/token"]
        dummy_creds = {"username": "test", "password": "test"}

        for path in login_paths:
            try:
                url = urljoin(base_url, path)
                res = await client.post(url, json=dummy_creds)
                text = res.text
                # Look for JWT pattern in response
                match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', text)
                if match:
                    return match.group(0)
            except (httpx.RequestError, httpx.TimeoutException):
                continue
        return None

    def _crack_jwt_secret(self, token, secrets):
        """Try HMAC signing with each secret and compare signature."""
        import hmac
        import hashlib

        parts = token.split(".")
        message = f"{parts[0]}.{parts[1]}".encode()
        original_sig = self._b64_decode(parts[2])

        for secret in secrets:
            try:
                computed = hmac.new(
                    secret.encode(), message, hashlib.sha256
                ).digest()
                if computed == original_sig:
                    return secret
            except Exception:
                continue
        return None

    def _b64_decode(self, s):
        """Base64url decode with padding."""
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    # ─────────────────────────────────────────
    # 4. AUTH & ACCESS CONTROL (ORIGINAL)
    # ─────────────────────────────────────────
    async def _test_auth(self, client, base_url, endpoints):
        findings = []

        # Build an unauthenticated client
        unauth_client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=True,
            follow_redirects=True
        )

        try:
            for url in endpoints:
                async with self.semaphore:
                    try:
                        # Hit endpoint with no auth header
                        res = await unauth_client.get(url)

                        if res.status_code == 200:
                            # Check if it returned actual data vs empty/error
                            body = res.text
                            if len(body) > 50 and not self._is_public_endpoint(url):
                                findings.append(self._finding(
                                    ftype="Unauthenticated API Access",
                                    severity="High",
                                    url=url,
                                    desc="Endpoint returns data without any authentication. "
                                         "Verify this is intentional for a public endpoint.",
                                    evidence=f"HTTP 200 with {len(body)} bytes, no auth required"
                                ))

                        # ── Admin endpoint without auth ────
                        if any(k in url.lower() for k in ["admin", "internal", "management"]):
                            if res.status_code in (200, 201, 403):
                                severity = "Critical" if res.status_code == 200 else "Medium"
                                findings.append(self._finding(
                                    ftype="Admin Endpoint Accessible",
                                    severity=severity,
                                    url=url,
                                    desc=f"Admin/internal endpoint responded with HTTP "
                                         f"{res.status_code}. Admin routes must require auth.",
                                    evidence=f"GET {url} → {res.status_code}"
                                ))

                    except (httpx.RequestError, httpx.TimeoutException):
                        continue
        finally:
            await unauth_client.aclose()

        return findings

    def _is_public_endpoint(self, url):
        public = ["/health", "/ping", "/status", "/docs", "/openapi", "/swagger"]
        return any(p in url.lower() for p in public)

    # ─────────────────────────────────────────
    # 5. BOLA / IDOR (ORIGINAL)
    # ─────────────────────────────────────────
    async def _test_bola(self, client, endpoints):
        """
        Broken Object Level Authorization:
        Try accessing object IDs that belong to other users.
        e.g. /api/users/1, /api/users/2, /api/orders/999
        """
        findings = []
        id_pattern = re.compile(r'/([\w-]+)/(\d+|[a-f0-9-]{36})(/|$)')

        for url in endpoints:
            match = id_pattern.search(url)
            if not match:
                continue

            resource = match.group(1)
            current_id = match.group(2)

            # Generate adjacent IDs to test
            test_ids = self._generate_test_ids(current_id)

            async with self.semaphore:
                for test_id in test_ids:
                    test_url = url.replace(
                        f"/{resource}/{current_id}",
                        f"/{resource}/{test_id}"
                    )
                    try:
                        res = await client.get(test_url)

                        if res.status_code == 200 and len(res.text) > 20:
                            findings.append(self._finding(
                                ftype="Broken Object Level Authorization (BOLA/IDOR)",
                                severity="Critical",
                                url=test_url,
                                desc=f"Accessed /{resource}/{test_id} which may belong to "
                                     f"another user. Server returned HTTP 200 with data. "
                                     f"Verify ownership is enforced server-side.",
                                evidence=f"GET {test_url} → 200 OK ({len(res.text)} bytes)"
                            ))
                            break  # One confirmed hit is enough per endpoint

                    except (httpx.RequestError, httpx.TimeoutException):
                        continue

        return findings

    def _generate_test_ids(self, current_id):
        """Generate nearby IDs to probe."""
        try:
            n = int(current_id)
            return [str(n + 1), str(n + 2), str(max(1, n - 1)), "1", "2", "9999"]
        except ValueError:
            # UUID or slug — return common test values
            return ["1", "2", "admin", "test", "00000000-0000-0000-0000-000000000001"]

    # ─────────────────────────────────────────
    # 6. RATE LIMITING (ORIGINAL)
    # ─────────────────────────────────────────
    async def _test_rate_limiting(self, client, base_url, endpoints):
        findings = []

        # Pick a small subset of endpoints to hammer
        targets = [
            ep for ep in endpoints
            if any(k in ep.lower() for k in ["login", "auth", "token", "password"])
        ][:3]

        if not targets:
            targets = [base_url]

        for url in targets:
            async with self.semaphore:
                try:
                    # Send rapid requests with small delays
                    status_codes = []
                    for i in range(20):
                        try:
                            res = await client.post(url, json={})
                            status_codes.append(res.status_code)
                            # Add small delay to avoid overwhelming
                            if i % 5 == 0:
                                await asyncio.sleep(0.1)
                        except (httpx.RequestError, httpx.TimeoutException):
                            continue

                    # If we never got a 429, rate limiting isn't enforced
                    if status_codes and 429 not in status_codes:
                        findings.append(self._finding(
                            ftype="No Rate Limiting Detected",
                            severity="High",
                            url=url,
                            desc="Endpoint accepted 20 rapid requests with no rate limiting "
                                 "(no HTTP 429 returned). Auth endpoints without rate limiting "
                                 "are vulnerable to brute-force and credential stuffing attacks.",
                            evidence=f"20 requests sent, status codes: {set(status_codes)}"
                        ))

                except Exception as e:
                    logger.debug(f"Rate limit test error: {e}")

        return findings

    # ─────────────────────────────────────────
    # 7. HTTP METHOD ABUSE (ORIGINAL)
    # ─────────────────────────────────────────
    async def _test_http_methods(self, client, endpoints):
        findings = []

        for url in endpoints[:20]:  # limit to avoid explosion
            async with self.semaphore:
                try:
                    allowed_methods = []

                    for method in HTTP_METHODS:
                        res = await client.request(method, url)
                        if res.status_code not in (404, 405, 501):
                            allowed_methods.append(method)

                    # Flag dangerous methods if allowed
                    dangerous = {"DELETE", "PUT", "PATCH"} & set(allowed_methods)
                    if dangerous:
                        findings.append(self._finding(
                            ftype="Dangerous HTTP Methods Allowed",
                            severity="Medium",
                            url=url,
                            desc=f"Endpoint allows potentially dangerous HTTP methods: "
                                 f"{', '.join(dangerous)}. Ensure these require proper "
                                 f"authentication and authorization.",
                            evidence=f"Allowed: {', '.join(allowed_methods)}"
                        ))

                    # TRACE enabled — enables XST attacks
                    trace_res = await client.request("TRACE", url)
                    if trace_res.status_code == 200:
                        findings.append(self._finding(
                            ftype="HTTP TRACE Method Enabled",
                            severity="Medium",
                            url=url,
                            desc="HTTP TRACE is enabled. This can be used in Cross-Site Tracing "
                                 "(XST) attacks to steal cookies and auth headers.",
                            evidence="TRACE → HTTP 200"
                        ))

                except (httpx.RequestError, httpx.TimeoutException):
                    continue

        return findings

    # ─────────────────────────────────────────
    # 8. SENSITIVE DATA EXPOSURE (ORIGINAL)
    #极────────────────────────────────────────
    async def _test_data_exposure(self, client, endpoints):
        findings = []

        for url in endpoints:
            async with self.semaphore:
                try:
                    res = await client.get(url)
                    if res.status_code != 200:
                        continue

                    body_lower = res.text.lower()

                    for field in SENSITIVE_FIELDS:
                        if f'"{field}"' in body_lower or f"'{field}'" in body_lower:
                            findings.append(self._finding(
                                ftype="Sensitive Field in API Response",
                                severity="High",
                                url=url,
                                desc=f"API response contains field '{field}'. Ensure sensitive "
                                     f"fields are stripped before returning to the client.",
                                evidence=f"Field '{field}' found in response body"
                            ))

                    # Stack trace / debug info leaked
                    debug_signals = [
                        "traceback", "stack trace", "at line",
                        "sqlexception", "syntaxerror", "django.db",
                        "internal server error", "exception in thread"
                    ]
                    for signal in debug_signals:
                        if signal in body_lower:
                            findings.append(self._finding(
                                ftype="Debug / Stack Trace in API Response",
                                severity="High",
                                url=url,
                                desc="API response leaks debug information or a stack trace. "
                                     "This reveals internal file paths, library versions, "
                                     "and code structure to attackers.",
                                evidence=f"Detected: '{signal}' in response"
                            ))
                            break

                except (httpx.RequestError, httpx.TimeoutException):
                    continue

        return findings

    # ─────────────────────────────────────────
    # 9. SECURITY HEADERS (ORIGINAL)
    # ─────────────────────────────────────────
    async def _test_security_headers(self, client, base_url):
        findings = []

        required_headers = {
            "X-Content-Type-Options":    ("nosniff", "Medium",
                                          "Missing X-Content-Type-Options: nosniff. Browsers may "
                                          "MIME-sniff responses and execute non-script content as scripts."),
            "X-Frame-Options":           (None, "Medium",
                                          "Missing X-Frame-Options. API responses could be framed "
                                          "in a malicious page for clickjacking."),
            "Strict-Transport-Security": (None, "High",
                                          "Missing HSTS header. Clients may connect over HTTP, "
                                          "exposing tokens and data to interception."),
            "极ontent-Security-Policy":   (None, "Medium",
                                          "Missing Content-Security-Policy header."),
        }

        forbidden_headers = {
            "X-Powered-By":  "Reveals server technology stack (e.g. Express, PHP version).",
            "Server":        "Reveals web server software and version.",
            "X-AspNet-Version": "Reveals ASP.NET version.",
        }

        try:
            res = await client.get(base_url)
            resp_headers = {k.lower(): v for k, v in res.headers.items()}

            for header, (expected_val, severity, desc) in required_headers.items():
                if header.lower() not in resp_headers:
                    findings.append(self._finding(
                        ftype=f"Missing Security Header: {header}",
                        severity=severity,
                        url=base_url,
                        desc=desc,
                        evidence=f"Header '{header}' not present in response"
                    ))

            for header, desc in forbidden_headers.items():
                if header.lower() in resp_headers:
                    findings.append(self._finding(
                        ftype=f"Information Disclosure Header: {header}",
                        severity="Low",
                        url=base_url,
                        desc=desc,
                        evidence=f"{header}: {resp_headers[header.lower()]}"
                    ))

            # CORS misconfiguration
            cors_findings = self._check_cors(res.headers, base_url)
            findings.extend(cors_findings)

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.warning(f"Header check failed: {e}")

        return findings

    def _check_cors(self, headers, url):
        findings = []
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "false")

        if acao == "*" and acac.lower() == "true":
            findings.append(self._finding(
                ftype="CORS Misconfiguration: Wildcard with Credentials",
                severity="Critical",
                url=url,
                desc="API sets Access-Control-Allow-Origin: * combined with "
                     "Access-Control-Allow-Credentials: true. This combination is rejected "
                     "by browsers but signals a dangerous intent — any origin can read "
                     "credentialed responses if misconfigured further.",
                evidence=f"ACAO: {acao} | ACAC: {acac}"
            ))
        elif acao == "*":
            findings.append(self._finding(
                ftype="CORS: Wildcard Origin Allowed",
                severity="Medium",
                url=url,
                desc="API allows requests from any origin (*). Acceptable for fully "
                     "public APIs, but verify no sensitive data is returned.",
                evidence=f"Access-Control-Allow-Origin: *"
            ))

        return findings

    # ─────────────────────────────────────────
    # 10. MASS ASSIGNMENT (ORIGINAL)
    # ─────────────────────────────────────────
    async def _test_mass_assignment(self, client, endpoints):
        """
        Send POST/PUT requests with extra fields like 'is_admin', 'role', 'balance'
        and check if the server accepts them without error.
        """
        findings = []
        privileged_fields = {
            "is_admin": True,
            "极le": "admin",
            "balance": 99999,
            "credits": 99999,
            "verified": True,
            "email_verified": True,
            "plan": "enterprise",
        }

        post_endpoints = [
            ep for ep in endpoints
            if any(k in ep.lower() for k in
                   ["user", "account", "profile", "register", "signup", "update"])
        ][:5]

        for url in post_endpoints:
            async with self.semaphore:
                try:
                    res = await client.post(url, json=privileged_fields)

                    # If accepted (not 400/422/403), flag it
                    if res.status_code in (200, 201):
                        body = res.text.lower()
                        # Check if any of our injected fields are reflected
                        reflected = [
                            f for f in privileged_fields
                            if f in body
                        ]
                        if reflected:
                            findings.append(self._finding(
                                ftype="Mass Assignment Vulnerability",
                                severity="Critical",
                                url=url,
                                desc="API accepted privileged fields in request body and "
                                     "reflected them in the response. An attacker could set "
                                     "'is_admin: true' or 'role: admin' during registration "
                                     "to escalate privileges.",
                                evidence=f"Reflected fields: {reflected}"
                            ))

                except (httpx.RequestError, httpx.TimeoutException):
                    continue

        return findings

    # ─────────────────────────────────────────
    # HELPER: BUILD FINDING DICT (ORIGINAL)
    # ─────────────────────────────────────────
    def _finding(self, ftype, severity, url, desc, evidence=""):
        return {
            "type":        ftype,
            "severity":    severity,
            "url":         url,
            "description": desc,
            "evidence":    evidence,
            "confidence":  0.85,
        }

    def _build_headers(self, auth_token=None):
        headers = {
            "User-Agent":   "SentinelAI/1.0 Security Scanner",
            "Accept":       "application/json",
            "Content-Type": "application/json",
        }
        if auth_token:
            token = auth_token if auth_token.startswith("Bearer ") \
                else f"Bearer {auth_token}"
            headers["Authorization"] = token
        return headers
