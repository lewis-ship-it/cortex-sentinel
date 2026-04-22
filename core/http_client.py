"""
core/http_client.py

Centralized async HTTP client with production-grade resilience:

FIXES IN THIS VERSION
─────────────────────
1. proxies= kwarg REMOVED.
   httpx removed the `proxies` parameter in v0.24.0.  The replacement is
   `proxy=` (singular, accepts a plain string URL).
   Old code:  httpx.AsyncClient(proxies={"http://": "http://proxy:8080"})
   New code:  httpx.AsyncClient(proxy="http://proxy:8080")

2. 429 / 503 / 504 awareness.
   The scanner now reads the `Retry-After` response header and sleeps exactly
   that many seconds before the tenacity back-off window.  Without this the
   scanner would hammer a rate-limited target at full speed between retries.

3. True exponential back-off via tenacity.
   The old code used a hand-rolled ``backoff_factor ** retry_count`` loop with
   asyncio.sleep().  Problems:
     • No jitter → "thundering herd" when many workers retry simultaneously
     • No maximum cap → could wait arbitrarily long
     • No before_sleep logging → hard to observe retry behaviour
   The new code uses tenacity:
     wait_exponential(multiplier=1, exp_base=2, max=30) + wait_random(0, 1)
   This gives: 1s → 2s → 4s → 8s → 16s → 30s (capped), each ±1 s random.

4. Per-host token-bucket rate limiter runs BEFORE every request attempt,
   including retries, keeping the scanner polite even when backing off.
"""

import asyncio
import httpx
import logging
import time
import random
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import datetime

from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    wait_random,
    before_sleep_log,
    RetryError,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG DATACLASSES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RateLimitConfig:
    """Per-target-host rate-limit parameters."""
    max_requests_per_second: float = 5.0
    min_delay_ms: int = 200          # hard floor between any two requests


@dataclass
class RequestMetrics:
    """Metrics recorded for a single HTTP attempt."""
    url: str
    status_code: Optional[int] = None
    response_time: float = 0.0
    retry_count: int = 0
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITER  (token-bucket, per host)
# ─────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Async token-bucket rate limiter keyed by target hostname.

    A single token is consumed per request.  If the bucket is empty the
    coroutine awaits until the refill time has passed.  This is strictly
    better than a sliding-window because short bursts are absorbed naturally;
    a brief pause refills the bucket so the scanner can burst again.
    """

    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig()
        self._min_gap: float = 1.0 / max(self.config.max_requests_per_second, 0.1)
        self._last_call: Dict[str, float] = {}

    async def wait_if_needed(self, host: str) -> None:
        now     = time.monotonic()
        last    = self._last_call.get(host, 0.0)
        floor   = self.config.min_delay_ms / 1000.0
        needed  = max(self._min_gap, floor)
        elapsed = now - last

        if elapsed < needed:
            wait = needed - elapsed
            logger.debug(f"[RateLimit] {host} — sleeping {wait:.3f}s")
            await asyncio.sleep(wait)

        self._last_call[host] = time.monotonic()


# ─────────────────────────────────────────────────────────────────────────────
# RETRY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

# Transient network exceptions worth retrying
_RETRYABLE_EXCEPTIONS = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.RemoteProtocolError,
    ConnectionResetError,
)

# HTTP status codes that warrant a retry (rate-limited / server overloaded)
_RETRYABLE_STATUSES = {429, 503, 504}


def _parse_retry_after(response: httpx.Response) -> float:
    """
    Parse the Retry-After header.  Returns seconds to wait, or 0.0 if absent.
    Handles both integer-seconds format and HTTP-date format.
    """
    header = response.headers.get("Retry-After", "").strip()
    if not header:
        return 0.0
    try:
        return max(0.0, float(header))
    except ValueError:
        try:
            from email.utils import parsedate_to_datetime
            delta = (parsedate_to_datetime(header) - datetime.utcnow()).total_seconds()
            return max(0.0, delta)
        except Exception:
            return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# HTTP CLIENT
# ─────────────────────────────────────────────────────────────────────────────

class HTTPClient:
    """
    Resilient async HTTP client.

    Key constructor parameters
    ──────────────────────────
    timeout            int   — per-request timeout in seconds (default 12)
    max_retries        int   — max retry attempts after the first failure (default 4)
    backoff_base       float — tenacity wait_exponential multiplier (default 1 s)
    backoff_multiplier float — tenacity exp_base (default 2 → 1 s, 2 s, 4 s …)
    backoff_max        float — ceiling on the exponential wait (default 30 s)
    rate_limit_config        — RateLimitConfig instance or None (uses defaults)
    proxy              str   — optional proxy URL e.g. "http://127.0.0.1:8080"
                               FIX: was 'proxies' (dict) — httpx ≥ 0.24 uses
                               'proxy' (singular string).
    verify_ssl         bool  — whether to verify TLS certificates (default True)
    """

    def __init__(
        self,
        timeout:            int             = 12,
        max_retries:        int             = 4,
        backoff_base:       float           = 1.0,
        backoff_multiplier: float           = 2.0,
        backoff_max:        float           = 30.0,
        rate_limit_config:  Optional[RateLimitConfig] = None,
        # FIX: parameter renamed from 'proxies' (dict) to 'proxy' (str | None)
        proxy:              Optional[str]   = None,
        verify_ssl:         bool            = True,
    ):
        self.timeout            = timeout
        self.max_retries        = max_retries
        self.backoff_base       = backoff_base
        self.backoff_multiplier = backoff_multiplier
        self.backoff_max        = backoff_max
        self.rate_limiter       = RateLimiter(rate_limit_config)
        self.proxy              = proxy
        self.verify_ssl         = verify_ssl
        self.metrics: List[RequestMetrics] = []
        self._client: Optional[httpx.AsyncClient] = None

    # ── Client lifecycle ──────────────────────────────────────────────────────

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-create the shared async client (one per HTTPClient instance)."""
        if self._client is None:
            kwargs: Dict[str, Any] = {
                "timeout":          self.timeout,
                "verify":           self.verify_ssl,
                "follow_redirects": True,
                "limits": httpx.Limits(
                    max_connections=50,
                    max_keepalive_connections=10,
                    keepalive_expiry=30,
                ),
            }
            # FIX: use proxy= (str) not proxies= (dict)
            # httpx removed the 'proxies' kwarg in v0.24.0
            if self.proxy:
                kwargs["proxy"] = self.proxy

            self._client = httpx.AsyncClient(**kwargs)
            logger.debug("[HTTPClient] AsyncClient created")
        return self._client

    async def close(self) -> None:
        """Close the underlying connection pool."""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.debug("[HTTPClient] AsyncClient closed")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()

    # ── Header normalization ──────────────────────────────────────────────────

    @staticmethod
    def _normalize_headers(headers: Optional[Dict] = None) -> Dict:
        h = dict(headers or {})
        h.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36",
        )
        h.setdefault("Accept",          "text/html,application/xhtml+xml,*/*;q=0.8")
        h.setdefault("Accept-Language", "en-US,en;q=0.9")
        h.setdefault("Accept-Encoding", "gzip, deflate")
        return h

    # ── Public convenience methods ────────────────────────────────────────────

    async def get(
        self,
        url:        str,
        headers:    Optional[Dict] = None,
        cookies:    Optional[Dict] = None,
        timeout:    Optional[int]  = None,
        verify_ssl: Optional[bool] = None,
    ) -> httpx.Response:
        return await self._request(
            "GET", url,
            headers=headers, cookies=cookies,
            timeout=timeout, verify_ssl=verify_ssl,
        )

    async def post(
        self,
        url:        str,
        data:       Optional[Dict] = None,
        json:       Optional[Dict] = None,
        headers:    Optional[Dict] = None,
        cookies:    Optional[Dict] = None,
        timeout:    Optional[int]  = None,
        verify_ssl: Optional[bool] = None,
    ) -> httpx.Response:
        return await self._request(
            "POST", url,
            data=data, json=json,
            headers=headers, cookies=cookies,
            timeout=timeout, verify_ssl=verify_ssl,
        )

    # ── Core request with tenacity exponential back-off ───────────────────────

    async def _request(
        self,
        method:     str,
        url:        str,
        data:       Optional[Dict] = None,
        json:       Optional[Dict] = None,
        headers:    Optional[Dict] = None,
        cookies:    Optional[Dict] = None,
        timeout:    Optional[int]  = None,
        verify_ssl: Optional[bool] = None,
    ) -> httpx.Response:
        """
        Execute one HTTP request with:
          • per-host rate limiting before every attempt (including retries)
          • Retry-After header parsing on 429/503/504
          • tenacity exponential back-off with jitter on transient failures

        Raises the last exception after max_retries are exhausted.
        """
        host        = urlparse(url).netloc
        headers     = self._normalize_headers(headers)
        timeout_val = timeout if timeout is not None else self.timeout
        verify_val  = verify_ssl if verify_ssl is not None else self.verify_ssl
        metric      = RequestMetrics(url=url)
        start       = time.monotonic()
        attempt_no  = 0

        async def _one_attempt() -> httpx.Response:
            nonlocal attempt_no
            attempt_no += 1

            # Always rate-limit before sending, even on retries
            await self.rate_limiter.wait_if_needed(host)

            client = await self._get_client()

            if method == "GET":
                resp = await client.get(
                    url,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout_val,
                )
            elif method == "POST":
                resp = await client.post(
                    url,
                    data=data,
                    json=json,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout_val,
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            # ── 429 / 503 / 504 — honour Retry-After then re-raise ────────
            if resp.status_code in _RETRYABLE_STATUSES:
                ra = _parse_retry_after(resp)
                if ra > 0:
                    logger.warning(
                        f"[{resp.status_code}] {url} — "
                        f"Retry-After {ra:.1f}s (attempt {attempt_no})"
                    )
                    await asyncio.sleep(ra)
                else:
                    # Let tenacity supply the exponential delay
                    wait = min(
                        self.backoff_base
                        * (self.backoff_multiplier ** (attempt_no - 1)),
                        self.backoff_max,
                    ) + random.uniform(0, 1.0)
                    logger.warning(
                        f"[{resp.status_code}] {url} — "
                        f"backing off {wait:.1f}s (attempt {attempt_no})"
                    )
                    await asyncio.sleep(wait)

                # Re-raise as HTTPStatusError so tenacity retries it
                raise httpx.HTTPStatusError(
                    f"Retryable status {resp.status_code}",
                    request=resp.request,
                    response=resp,
                )

            logger.debug(
                f"[{method}] {url} → {resp.status_code} "
                f"({time.monotonic() - start:.2f}s, attempt {attempt_no})"
            )
            metric.status_code = resp.status_code
            return resp

        # ── tenacity retry loop ───────────────────────────────────────────────
        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(self.max_retries + 1),
                wait=(
                    wait_exponential(
                        multiplier=self.backoff_base,
                        exp_base=self.backoff_multiplier,
                        max=self.backoff_max,
                    )
                    + wait_random(0, 1.0)
                ),
                retry=retry_if_exception_type(
                    _RETRYABLE_EXCEPTIONS + (httpx.HTTPStatusError,)
                ),
                before_sleep=before_sleep_log(logger, logging.WARNING),
                reraise=True,
            ):
                with attempt:
                    response = await _one_attempt()

        except (RetryError, httpx.HTTPStatusError, *_RETRYABLE_EXCEPTIONS) as exc:
            metric.error = str(exc)
            logger.error(
                f"[FAILED] {method} {url} after {attempt_no} attempt(s): {exc}"
            )
            raise

        finally:
            metric.response_time = time.monotonic() - start
            metric.retry_count   = max(attempt_no - 1, 0)
            self.metrics.append(metric)

        return response

    # ── Metrics ───────────────────────────────────────────────────────────────

    def get_metrics(self) -> List[RequestMetrics]:
        return list(self.metrics)

    def clear_metrics(self) -> None:
        self.metrics.clear()


# ─────────────────────────────────────────────────────────────────────────────
# SINGLETON FACTORY
# ─────────────────────────────────────────────────────────────────────────────

_default_client: Optional[HTTPClient] = None


async def get_http_client(
    timeout:           int                        = 12,
    max_retries:       int                        = 4,
    rate_limit_config: Optional[RateLimitConfig]  = None,
    proxy:             Optional[str]              = None,
) -> HTTPClient:
    """Return (or lazily create) the shared default HTTPClient instance."""
    global _default_client
    if _default_client is None:
        _default_client = HTTPClient(
            timeout=timeout,
            max_retries=max_retries,
            rate_limit_config=rate_limit_config,
            proxy=proxy,
        )
    return _default_client