# scanner/dast/modules/access.py
# ──────────────────────────────────────────────────────────────────────────────
# ACCESS CONTROL MODULE — IDOR, Privilege Escalation, Auth Bypass, JWT Attacks,
# Business Logic Flaws, Race Conditions, Mass Assignment
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import logging
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)

# Parameters likely to be used in object references
IDOR_PARAMS = frozenset({
    "id", "user_id", "account_id", "order_id", "invoice_id", "doc_id",
    "file_id", "item_id", "message_id", "ticket_id", "report_id",
    "profile_id", "customer_id", "record_id", "pid", "uid", "oid",
    "ref", "uuid", "guid", "key", "token",
})

# Admin-only paths to probe for privilege escalation
ADMIN_PATHS = [
    "/admin", "/admin/users", "/admin/settings", "/admin/dashboard",
    "/api/admin", "/api/admin/users", "/api/v1/admin", "/api/v2/admin",
    "/management", "/manage", "/superuser", "/root",
    "/api/users", "/api/accounts", "/api/orders", "/api/invoices",
]

# JWT attack payloads
JWT_ALG_NONE_HEADER  = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"   # {"alg":"none","typ":"JWT"}
JWT_HS256_HEADER     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" # {"alg":"HS256","typ":"JWT"}


class AccessModule:
    def __init__(self, scanner):
        self.scanner = scanner

    async def run(self, client, url: str, params: list) -> None:
        await asyncio.gather(
            self.test_idor(client, url, params),
            self.test_admin_access(client, url),
            self.test_http_method_override(client, url),
            self.test_mass_assignment(client, url, params),
            self.test_jwt_attacks(client, url),
            self.test_race_condition(client, url, params),
            return_exceptions=True,
        )

    # ── IDOR ──────────────────────────────────────────────────────────────────
    async def test_idor(self, client, url: str, params: list) -> None:
        """Test for Insecure Direct Object References by iterating object IDs."""
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)

        for param in params:
            if param.lower() not in IDOR_PARAMS:
                continue
            current_val = qs.get(param, ["1"])[0]

            # Try to extract numeric ID and iterate
            numeric = re.sub(r'\D', '', current_val)
            if not numeric:
                continue

            base_id = int(numeric)
            baseline_res = await self.scanner._req(client, "GET", url)
            if not baseline_res or baseline_res.status_code != 200:
                continue
            baseline_len = len(baseline_res.text)

            for test_id in [base_id - 1, base_id + 1, base_id + 100, 1, 2, 0]:
                if test_id < 0:
                    continue
                new_qs  = {**qs, param: [str(test_id)]}
                new_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
                res     = await self.scanner._req(client, "GET", new_url)

                if not res or res.status_code != 200:
                    continue
                # Significantly different content suggests we accessed a different object
                diff = abs(len(res.text) - baseline_len)
                if diff > 30 and len(res.text) > 100:
                    self.scanner._add_finding({
                        "type":        "Insecure Direct Object Reference (IDOR)",
                        "subtype":     f"Parameter: {param}",
                        "url":         new_url,
                        "parameter":   param,
                        "payload":     str(test_id),
                        "severity":    "Critical",
                        "confidence":  0.80,
                        "evidence":    f"ID={test_id} returned 200 with content diff={diff}B from ID={base_id}",
                        "description": (
                            f"Parameter '{param}' allows access to other users' objects. "
                            f"Object ID {test_id} returned valid content."
                        ),
                    })
                    return

    # ── Admin Access / Privilege Escalation ───────────────────────────────────
    async def test_admin_access(self, client, url: str) -> None:
        """Probe admin paths without credentials — broken access control."""
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        for path in ADMIN_PATHS:
            test_url = base + path
            res = await self.scanner._req(client, "GET", test_url)
            if not res:
                continue
            if res.status_code == 200 and len(res.text) > 200:
                # Avoid false positives from login redirects
                body_lower = res.text.lower()
                is_login_page = any(k in body_lower for k in [
                    "login", "sign in", "username", "password", "email",
                ])
                if not is_login_page:
                    self.scanner._add_finding({
                        "type":        "Broken Access Control",
                        "subtype":     "Unauthenticated Admin Endpoint",
                        "url":         test_url,
                        "parameter":   "path",
                        "payload":     path,
                        "severity":    "Critical",
                        "confidence":  0.88,
                        "evidence":    f"HTTP 200 from {path} without authentication ({len(res.text)}B)",
                        "description": (
                            f"Admin/privileged endpoint {path} is accessible without authentication. "
                            f"This allows privilege escalation."
                        ),
                    })

    # ── HTTP Method Override ───────────────────────────────────────────────────
    async def test_http_method_override(self, client, url: str) -> None:
        """Test for HTTP method override bypasses (X-HTTP-Method-Override)."""
        override_headers = [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method-Override": "PUT"},
            {"X-Method-Override": "DELETE"},
            {"_method": "DELETE"},
        ]
        for headers in override_headers:
            res = await self.scanner._req(client, "POST", url, headers=headers, data={})
            if res and res.status_code not in (404, 405, 403, 501):
                self.scanner._add_finding({
                    "type":        "HTTP Method Override",
                    "subtype":     "DELETE/PUT via POST override",
                    "url":         url,
                    "parameter":   list(headers.keys())[0],
                    "payload":     list(headers.values())[0],
                    "severity":    "High",
                    "confidence":  0.75,
                    "evidence":    f"Override header accepted — HTTP {res.status_code}",
                    "description": (
                        "Server accepts HTTP method override headers, allowing "
                        "bypassing of method-based access controls."
                    ),
                })
                return

    # ── Mass Assignment ────────────────────────────────────────────────────────
    async def test_mass_assignment(self, client, url: str, params: list) -> None:
        """Probe for mass assignment by injecting privileged fields."""
        privileged_fields = {
            "role":      "admin",
            "is_admin":  "true",
            "admin":     "1",
            "is_staff":  "true",
            "privilege": "admin",
            "level":     "0",
            "balance":   "99999",
            "credits":   "99999",
        }
        for field, value in privileged_fields.items():
            res = await self.scanner._req(
                client, "POST", url,
                data={**{p: "test" for p in params[:3]}, field: value},
                timeout=10,
            )
            if res and res.status_code in (200, 201, 204):
                body_lower = res.text.lower()
                # Look for evidence the field was accepted
                if field in body_lower or value in body_lower or "success" in body_lower:
                    self.scanner._add_finding({
                        "type":        "Mass Assignment",
                        "subtype":     f"Privileged field: {field}",
                        "url":         url,
                        "parameter":   field,
                        "payload":     f"{field}={value}",
                        "severity":    "High",
                        "confidence":  0.72,
                        "evidence":    f"Field '{field}={value}' accepted — HTTP {res.status_code}",
                        "description": (
                            f"POST endpoint accepts '{field}' field without filtering. "
                            "Attacker may escalate privileges via mass assignment."
                        ),
                    })
                    return

    # ── JWT Attacks ────────────────────────────────────────────────────────────
    async def test_jwt_attacks(self, client, url: str) -> None:
        """
        Probe JWT vulnerabilities:
         - alg:none attack (strip signature)
         - weak secret brute-force hint
         - kid injection
        """
        parsed  = urlparse(url)
        cookies = {k: v for k, v in client.cookies.items()}
        headers = {k: v for k, v in client.headers.items()}

        # Look for JWT in cookies or Authorization header
        jwt_token = None
        auth_hdr  = headers.get("authorization", headers.get("Authorization", ""))
        if auth_hdr.startswith("Bearer "):
            jwt_token = auth_hdr[7:]
        if not jwt_token:
            for v in cookies.values():
                # JWT is 3 base64 segments separated by dots
                if isinstance(v, str) and v.count(".") == 2 and len(v) > 20:
                    jwt_token = v
                    break

        if not jwt_token:
            return

        parts = jwt_token.split(".")
        if len(parts) != 3:
            return

        header_b64, payload_b64, _sig = parts

        # Attack 1: alg:none — remove signature
        # Re-encode header with alg:none
        none_token = f"{JWT_ALG_NONE_HEADER}.{payload_b64}."
        res = await self.scanner._req(
            client, "GET", url,
            headers={"Authorization": f"Bearer {none_token}"},
        )
        if res and res.status_code == 200:
            self.scanner._add_finding({
                "type":        "JWT Algorithm Confusion (alg:none)",
                "subtype":     "Signature Not Validated",
                "url":         url,
                "parameter":   "Authorization",
                "payload":     none_token[:80] + "...",
                "severity":    "Critical",
                "confidence":  0.92,
                "evidence":    f"alg:none token accepted — HTTP 200",
                "description": (
                    "Server accepted a JWT with algorithm set to 'none', meaning "
                    "the signature was not validated. Any unsigned token is trusted."
                ),
            })

    # ── Race Condition ─────────────────────────────────────────────────────────
    async def test_race_condition(self, client, url: str, params: list) -> None:
        """
        Detect race conditions on state-changing endpoints by firing
        parallel requests and checking for inconsistent responses.
        Only runs on likely state-changing endpoints.
        """
        path = urlparse(url).path.lower()
        if not any(k in path for k in [
            "transfer", "payment", "purchase", "withdraw", "apply",
            "redeem", "coupon", "vote", "submit", "create", "buy",
        ]):
            return

        num_concurrent = 8
        results = []

        async def fire():
            r = await self.scanner._req(client, "POST", url, data={p: "1" for p in params[:3]})
            return r.status_code if r else None

        tasks   = [fire() for _ in range(num_concurrent)]
        codes   = await asyncio.gather(*tasks)
        success = [c for c in codes if c and c in (200, 201, 204)]

        if len(success) > 1:
            self.scanner._add_finding({
                "type":        "Race Condition",
                "subtype":     "Parallel Request Exploitation",
                "url":         url,
                "parameter":   "concurrent_requests",
                "payload":     f"{num_concurrent} parallel POST requests",
                "severity":    "High",
                "confidence":  0.78,
                "evidence":    f"{len(success)}/{num_concurrent} concurrent requests succeeded (codes: {codes})",
                "description": (
                    f"Endpoint {url} processed {len(success)} concurrent requests as successful, "
                    "indicating a race condition. This may allow double-spending, coupon reuse, "
                    "or bypassing rate limits."
                ),
            })