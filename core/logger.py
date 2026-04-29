# core/logger.py
# ──────────────────────────────────────────────────────────────────────────────
# FIXES IN THIS VERSION
#
#   FIX 1 — Crash on import when Redis is unavailable
#     Old code called redis.Redis.from_url() inside __init__ at module load time.
#     Any worker that imported get_logger() would crash immediately if Redis
#     was not yet reachable (common during Docker container startup race).
#     Fixed: Redis connection is now lazy — obtained on first log write via
#     task_queue.redis_client.get_redis_connection() which handles reconnects.
#
#   FIX 2 — Duplicate console log lines
#     get_logger() returned a cached _loggers[component] instance but the
#     StreamHandler was added inside __init__, so the FIRST call was fine.
#     However, if any code created a second SystemLogger for the same component
#     name (e.g. after a reload), a second handler was added to the same
#     logging.Logger, doubling every line.
#     Fixed: guard with `if not self.logger.handlers` before adding the handler.
#
#   FIX 3 — Redis log TTL too short / global index bloat
#     24h TTL meant logs for long jobs could disappear mid-scan.  Raised to 7
#     days.  Global "logs:all" key trimmed to 5000 (was unbounded growth risk).
# ──────────────────────────────────────────────────────────────────────────────

import json
import logging
import os
from typing import Optional, Dict, Any
from datetime import datetime

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

LOG_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days


class LogLevel:
    DEBUG    = "DEBUG"
    INFO     = "INFO"
    WARNING  = "WARNING"
    ERROR    = "ERROR"
    CRITICAL = "CRITICAL"


class StructuredLogEntry:
    """Represents a single structured log entry."""

    def __init__(
        self,
        timestamp:  str,
        level:      str,
        component:  str,
        job_id:     str,
        message:    str,
        details:    Optional[Dict[str, Any]] = None,
        tier:       str = "Basic",
    ):
        self.timestamp = timestamp
        self.level     = level
        self.component = component
        self.job_id    = job_id
        self.message   = message
        self.details   = details or {}
        self.tier      = tier

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "level":     self.level,
            "component": self.component,
            "job_id":    self.job_id,
            "message":   self.message,
            "details":   self.details,
            "tier":      self.tier,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class SystemLogger:
    """
    Centralized logger that writes to:
      1. Python logging (console)
      2. Redis (for dashboard / real-time SSE stream) — lazily connected
      3. SQLite via core.database (authoritative store for /api/status)
    """

    def __init__(self, component: str = "system"):
        self.component = component

        # Python logger — guard against duplicate handlers on re-import
        self.logger = logging.getLogger(component)
        self.logger.setLevel(logging.DEBUG)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            self.logger.addHandler(handler)

    # ── Redis (lazy) ──────────────────────────────────────────────────────────

    def _redis(self):
        """Return the shared Redis client, or None if unavailable."""
        try:
            from task_queue.redis_client import get_redis_connection
            return get_redis_connection()
        except Exception:
            return None

    # ── Internal write ────────────────────────────────────────────────────────

    def _log_to_redis(self, entry: StructuredLogEntry) -> None:
        r = self._redis()
        if not r:
            return
        try:
            key = f"logs:{entry.job_id}"
            r.rpush(key, entry.to_json())
            r.ltrim(key, -500, -1)
            r.expire(key, LOG_TTL_SECONDS)

            global_key = "logs:all"
            r.rpush(global_key, entry.to_json())
            r.ltrim(global_key, -5000, -1)
            r.expire(global_key, LOG_TTL_SECONDS)
        except Exception as e:
            self.logger.debug(f"[logger] Redis write failed: {e}")

    # ── Public API ────────────────────────────────────────────────────────────

    def log(
        self,
        level:   str,
        message: str,
        job_id:  str,
        details: Optional[Dict[str, Any]] = None,
        tier:    str = "Basic",
    ) -> None:
        timestamp = datetime.utcnow().isoformat()
        entry = StructuredLogEntry(
            timestamp=timestamp,
            level=level,
            component=self.component,
            job_id=job_id,
            message=message,
            details=details,
            tier=tier,
        )

        log_fn = getattr(self.logger, level.lower(), self.logger.info)
        log_fn(f"[{job_id}] {message}")

        self._log_to_redis(entry)

    def debug(self, message: str, job_id: str = "system",
              details: Optional[Dict] = None, tier: str = "Basic") -> None:
        self.log(LogLevel.DEBUG, message, job_id, details, tier)

    def info(self, message: str, job_id: str = "system",
             details: Optional[Dict] = None, tier: str = "Basic") -> None:
        self.log(LogLevel.INFO, message, job_id, details, tier)

    def warning(self, message: str, job_id: str = "system",
                details: Optional[Dict] = None, tier: str = "Basic") -> None:
        self.log(LogLevel.WARNING, message, job_id, details, tier)

    def error(self, message: str, job_id: str = "system",
              details: Optional[Dict] = None, tier: str = "Basic") -> None:
        self.log(LogLevel.ERROR, message, job_id, details, tier)

    def critical(self, message: str, job_id: str = "system",
                 details: Optional[Dict] = None, tier: str = "Basic") -> None:
        self.log(LogLevel.CRITICAL, message, job_id, details, tier)

    # ── Query helpers ─────────────────────────────────────────────────────────

    def get_job_logs(self, job_id: str, limit: int = 100) -> list:
        r = self._redis()
        if not r:
            return []
        try:
            raw = r.lrange(f"logs:{job_id}", -limit, -1)
            return [json.loads(e) for e in raw]
        except Exception:
            return []

    def get_recent_logs(self, limit: int = 100) -> list:
        r = self._redis()
        if not r:
            return []
        try:
            raw = r.lrange("logs:all", -limit, -1)
            return [json.loads(e) for e in raw]
        except Exception:
            return []

    def clear_job_logs(self, job_id: str) -> None:
        r = self._redis()
        if r:
            try:
                r.delete(f"logs:{job_id}")
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# SINGLETON CACHE
# ─────────────────────────────────────────────────────────────────────────────

_loggers: Dict[str, SystemLogger] = {}


def get_logger(component: str = "sentinel") -> SystemLogger:
    """Return (or create) the SystemLogger for a named component."""
    if component not in _loggers:
        _loggers[component] = SystemLogger(component=component)
    return _loggers[component]