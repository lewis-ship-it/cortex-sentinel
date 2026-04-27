
# scanner/auth.py
# ──────────────────────────────────────────────────────────────────────────────
# FIXES vs previous version:
#   1. login() had no `tier` parameter — auth_worker passes tier but it was lost.
#   2. No Bearer token support — Professional tier needs Authorization header auth.
#   3. No CSRF token handling — login to most modern apps requires CSRF token.
#   4. No redirect following detection — login success often ends with a redirect.
#   5. No error logging — silent None return made debugging impossible.
# ──────────────────────────────────────────────────────────────────────────────

import logging
import re
import requests

logger = logging.getLogger(__name__)


class Authenticator:

    def login(self, login_url: str, username: str, password: str, tier: str = "Basic") -> dict | None:
        """
        Authenticate against a login form and return a session dict
        containing cookies and headers.

        Returns None on failure — caller should proceed unauthenticated.
        """
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })

        try:
            # Step 1: GET the login page to harvest CSRF tokens
            get_res = session.get(login_url, timeout=10, allow_redirects=True)

            # Extract common CSRF token patterns
            csrf_token = self._extract_csrf(get_res.text)

            # Step 2: POST credentials
            data = {
                "username":  username,
                "password":  password,
                "email":     username,   # some apps use email field
                "login":     username,
                "user":      username,
            }
            if csrf_token:
                data.update({
                    "csrf_token":            csrf_token,
                    "_token":                csrf_token,
                    "csrf":                  csrf_token,
                    "authenticity_token":    csrf_token,
                })
                logger.debug(f"[AUTH] CSRF token harvested: {csrf_token[:20]}...")

            post_res = session.post(
                login_url, data=data, timeout=12,
                allow_redirects=True,
            )

            # Detect login failure heuristics
            failure_indicators = [
                "invalid password", "incorrect password", "wrong password",
                "login failed", "authentication failed", "invalid credentials",
                "incorrect credentials", "bad credentials",
            ]
            body_lower = post_res.text.lower()
            if any(ind in body_lower for ind in failure_indicators):
                logger.warning(f"[AUTH] Login failure indicators found for {login_url}")
                return None

            if post_res.status_code not in (200, 302):
                logger.warning(f"[AUTH] Unexpected status {post_res.status_code} from {login_url}")
                return None

            cookies = session.cookies.get_dict()
            if not cookies:
                logger.warning(f"[AUTH] No session cookies set after login to {login_url}")
                # Still return — some apps use token-based auth
            else:
                logger.info(f"[AUTH] Login successful — {len(cookies)} cookies set")

            return {
                "cookies": cookies,
                "headers": {
                    k: v for k, v in session.headers.items()
                    if k.lower() not in ("user-agent", "accept-encoding")
                },
            }

        except requests.exceptions.ConnectionError:
            logger.error(f"[AUTH] Cannot connect to {login_url}")
            return None
        except requests.exceptions.Timeout:
            logger.error(f"[AUTH] Timeout connecting to {login_url}")
            return None
        except Exception as e:
            logger.error(f"[AUTH] Login error for {login_url}: {e}")
            return None

    def login_bearer(self, token_url: str, client_id: str, client_secret: str) -> dict | None:
        """
        OAuth2 client_credentials grant — returns Bearer token session.
        """
        try:
            res = requests.post(token_url, data={
                "grant_type":    "client_credentials",
                "client_id":     client_id,
                "client_secret": client_secret,
            }, timeout=10)
            res.raise_for_status()
            token = res.json().get("access_token")
            if token:
                return {
                    "cookies": {},
                    "headers": {"Authorization": f"Bearer {token}"},
                }
        except Exception as e:
            logger.error(f"[AUTH] Bearer token fetch failed: {e}")
        return None

    def _extract_csrf(self, html: str) -> str | None:
        """Extract CSRF token from common HTML patterns."""
        patterns = [
            r'<input[^>]+name=["\'](?:csrf_token|_token|csrf|authenticity_token)["\'][^>]+value=["\']([^"\']+)["\']',
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
            r'"csrf_token"\s*:\s*"([^"]+)"',
        ]
        for pat in patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

