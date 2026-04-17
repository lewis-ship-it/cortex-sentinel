# scanner/dast/modules/access.py
#
# FIXES:
#   - test_idor: baseline comparison added (was false-positiving on any 200)
#   - test_idor: now handles UUID patterns in addition to numeric IDs
#   - test_auth_panels: improved login success detection
#   - test_jwt_logic: fixed to handle httpx cookie jar properly
#   - Added account lockout check

import asyncio
import base64
import json
import logging
import re
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

_ID_PATTERN   = re.compile(r'(/[\w\-]+/)(\d+)(/|$)')
_UUID_PATTERN = re.compile(
    r'(/[\w\-]+/)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)',
    re.IGNORECASE,
)

AUTH_PANEL_PATHS = [
    "/admin", "/admin/login", "/administrator", "/wp-admin", "/wp-login.php",
    "/login", "/signin", "/user/login", "/auth/login",
    "/panel", "/dashboard", "/manage", "/phpmyadmin", "/pma",
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", ""), ("root", "root"),
    ("test", "test"), ("guest", "guest"), ("admin", "pass"),
]

USERNAME_FIELDS = ["username", "user", "email", "login", "uname"]
PASSWORD_FIELDS = ["password", "pass", "passwd", "pwd", "secret"]


class AccessModule:
    def __init__(self, scanner):
        self.scanner = scanner

    async def run(self, client, url: str, params: list) -> None:
        tasks = [
            self.test_jwt_logic(client),
            self.test_auth_panels(client, url),
            self.test_idor(client, url, params),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    # ── JWT analysis ──────────────────────────────────────────────────────────
    async def test_jwt_logic(self, client) -> None:
        """FIX: iterate cookies correctly via httpx cookie jar."""
        jwt_re = re.compile(r'ey[A-Za-z0-9\-_=]+\.ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*')
        cookie_str = " ".join(f"{c.name}={c.value}" for c in client.cookies.jar)
        auth_header = str(client.headers.get("Authorization", ""))
        source = cookie_str + " " + auth_header

        for token in jwt_re.findall(source):
            try:
                header_b64 = token.split(".")[0] + "==="
                header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
                if header.get("alg", "").lower() == "none":
                    self.scanner._add_finding({
                        "type": "Broken Authentication", "subtype": "JWT alg:none",
                        "url": "Session Token", "parameter": "Authorization/Cookie",
                        "payload": token[:60] + "...",
                        "severity": "Critical", "confidence": 1.0,
                        "evidence": f"alg={header.get('alg')}",
                        "description": "JWT with alg=none accepted — signature not verified. Any user can forge tokens.",
                    })
            except Exception:
                continue

    # ── IDOR ──────────────────────────────────────────────────────────────────
    async def test_idor(self, client, url: str, params: list) -> None:
        """
        FIX: compares response against baseline before flagging.
        Also detects IDs in URL path segments (not just query params).
        """
        parsed = urlparse(url)
        path   = parsed.path

        for pattern in (_ID_PATTERN, _UUID_PATTERN):
            m = pattern.search(path)
            if not m:
                continue

            original_id   = m.group(2)
            resource_name = m.group(1).strip("/")

            try:
                n        = int(original_id)
                test_ids = [str(n + 1), str(n + 2), str(max(1, n - 1)), "1", "9999"]
            except ValueError:
                test_ids = [
                    "00000000-0000-0000-0000-000000000001",
                    "00000000-0000-0000-0000-000000000002",
                ]

            baseline = await self.scanner._req(client, "GET", url)
            if not baseline or baseline.status_code != 200 or len(baseline.text) < 30:
                continue

            for test_id in test_ids:
                if test_id == original_id:
                    continue
                new_path = pattern.sub(
                    lambda x, tid=test_id: x.group(1) + tid + x.group(3), path, count=1
                )
                test_url = urlunparse(parsed._replace(path=new_path))
                res      = await self.scanner._req(client, "GET", test_url)
                if not res or res.status_code != 200:
                    continue

                size_ratio = len(res.text) / max(len(baseline.text), 1)
                if len(res.text) > 50 and 0.3 < size_ratio < 3.0:
                    self.scanner._add_finding({
                        "type": "IDOR / Broken Object Level Authorization",
                        "subtype": "Path ID Enumeration",
                        "url": test_url, "parameter": resource_name, "payload": test_id,
                        "severity": "High", "confidence": 0.75,
                        "evidence": (
                            f"ID {original_id}→{test_id} on /{resource_name}/. "
                            f"Got HTTP 200, {len(res.text)} bytes ({size_ratio:.1f}x baseline)."
                        ),
                        "description": f"/{resource_name}/{test_id} returned data without auth check.",
                    })
                    return

    # ── Auth panels + default creds ───────────────────────────────────────────
    async def test_auth_panels(self, client, base_url: str) -> None:
        base = base_url.rstrip("/")
        for path in AUTH_PANEL_PATHS:
            url = base + path
            res = await self.scanner._req(client, "GET", url)
            if not res or res.status_code not in (200, 401, 403):
                continue
            body = res.text.lower()
            if not any(kw in body for kw in ("password", "passwd", "login", "username", "sign in")):
                continue

            logger.info(f"[ACCESS] Login panel: {url}")

            u_field = self._guess_field(body, USERNAME_FIELDS)
            p_field = self._guess_field(body, PASSWORD_FIELDS)

            found_cred = None
            for username, password in DEFAULT_CREDS:
                data = {u_field: username, p_field: password}
                lr   = await self.scanner._req(client, "POST", url, data=data, timeout=15)
                if not lr:
                    continue
                if lr.status_code in (301, 302, 303):
                    loc = lr.headers.get("location", "")
                    if any(kw in loc.lower() for kw in ("dashboard", "admin", "panel", "home")):
                        found_cred = (username, password)
                        break
                lb = lr.text.lower()
                if (any(kw in lb for kw in ("dashboard", "logout", "welcome", "signed in"))
                        and not any(kw in lb for kw in ("invalid", "incorrect", "failed", "error"))):
                    found_cred = (username, password)
                    break

            if found_cred:
                self.scanner._add_finding({
                    "type": "Default Credentials Accepted",
                    "url": url, "parameter": "login form",
                    "payload": f"{found_cred[0]}:{found_cred[1]}",
                    "severity": "Critical", "confidence": 0.97,
                    "evidence": f"Login succeeded with {found_cred[0]}:{found_cred[1]}",
                    "description": f"Admin panel at {url} accepts default credentials.",
                })
            else:
                # Check for missing account lockout
                locked = False
                for _ in range(10):
                    r = await self.scanner._req(client, "POST", url,
                        data={u_field: "admin", p_field: "wrongpassword123"}, timeout=15)
                    if r and (r.status_code == 429 or any(
                        kw in r.text.lower() for kw in ("locked", "too many", "captcha", "blocked")
                    )):
                        locked = True
                        break
                if not locked:
                    self.scanner._add_finding({
                        "type": "Missing Account Lockout",
                        "url": url, "severity": "Medium", "confidence": 0.85,
                        "evidence": "10 failed logins — no lockout or 429",
                        "description": f"Login at {url} has no brute-force protection.",
                    })

    def _guess_field(self, html: str, candidates: list) -> str:
        for c in candidates:
            if f'name="{c}"' in html or f"name='{c}'" in html:
                return c
        return candidates[0]
