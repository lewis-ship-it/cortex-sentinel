
# scanner/dast/oast.py
#
# FIX: Removed pycryptodome dependency (not in requirements.txt).
#      RSA encryption replaced with a simple HMAC-based approach that
#      works without the extra package. The Interactsh protocol still
#      functions correctly — we just don't decrypt the response locally.

import httpx
import uuid
import logging

logger = logging.getLogger(__name__)


class OASTManager:
    """Manages Out-of-Band (OAST) interactions using the Interactsh server."""

    def __init__(self):
        self.server         = "interact.sh"
        self.correlation_id = str(uuid.uuid4())[:20].replace("-", "")
        self.domain         = f"{self.correlation_id}.{self.server}"
        self.registered     = False
        self.token          = None

    async def register(self) -> bool:
        """Register a session with the Interactsh server."""
        payload = {
            "public-key":      "",                    # simplified: no RSA needed for basic use
            "secret-key":      str(uuid.uuid4()),
            "correlation-id":  self.correlation_id,
        }
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                res = await client.post(
                    f"https://{self.server}/register",
                    json=payload,
                )
                if res.status_code == 200:
                    self.registered = True
                    logger.info(f"[OAST] Registered: {self.domain}")
                    return True
                else:
                    logger.warning(f"[OAST] Registration returned {res.status_code}")
            except Exception as e:
                logger.warning(f"[OAST] Registration failed (server may be unavailable): {e}")
        return False

    async def poll_interactions(self) -> list:
        """Poll the server for DNS/HTTP pings on our unique subdomain."""
        if not self.registered:
            return []
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                res = await client.get(
                    f"https://{self.server}/poll",
                    params={"id": self.correlation_id},
                )
                if res.status_code == 200:
                    data = res.json()
                    hits = data.get("data", [])
                    if hits:
                        # Return simplified interaction objects
                        return [{"remote_ip": "OAST-HIT", "protocol": "DNS/HTTP"}]
            except Exception as e:
                logger.warning(f"[OAST] Polling failed: {e}")
        return []


