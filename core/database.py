
"""
core/database.py
────────────────────────────────────────────────────────────────────────────────
Production-grade SQLite persistence layer for Sentinel Scanner.

FIXES IN THIS VERSION
─────────────────────
BUG 4 — save_vulnerabilities() silently dropped all ActiveScanner findings.
  ActiveScanner._add_finding() stores keys: "url", "parameter", "confidence".
  scan_worker evidence-gated path stores: "target_url", "param", "confidence_score".
  FindingRecord.model_fields filter discarded unrecognised keys silently.
  FIX: Normalise before constructing FindingRecord:
    "url"              → "target_url"
    "parameter"        → "param"
    "confidence_score" → "confidence"
    "evidence_snippet" → "evidence" (fallback)

update_job_status() — was missing default for progress argument.
  FIX: progress=0 default added; force=True bypasses state machine.

save_error_log() — referenced by workers but never defined.
  FIX: thin wrapper around add_log().

get_job_status()  — referenced by realtime.py but never defined.
  FIX: added.

get_log_messages() — now encodes component and stage so the JS log renderer
  gets the coloured label it expects (was missing stage/component keys).
────────────────────────────────────────────────────────────────────────────────
"""

import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "sentinel.db")

# ─────────────────────────────────────────────────────────────────────────────
# PYDANTIC MODELS
# ─────────────────────────────────────────────────────────────────────────────

class JobStatus(str, Enum):
    PENDING          = "pending"
    CRAWLING         = "crawling"
    SCANNING         = "scanning"
    EXPLOITING       = "exploiting"
    AGGREGATING      = "aggregating"
    MEMORY_ENRICHING = "memory_enriching"
    SCORING          = "scoring"
    REPORTING        = "reporting"
    DONE             = "done"
    FAILED           = "failed"


_VALID_TRANSITIONS: Dict[JobStatus, List[JobStatus]] = {
    JobStatus.PENDING:          [JobStatus.CRAWLING, JobStatus.SCANNING, JobStatus.FAILED],
    JobStatus.CRAWLING:         [JobStatus.SCANNING, JobStatus.FAILED],
    JobStatus.SCANNING:         [JobStatus.EXPLOITING, JobStatus.AGGREGATING, JobStatus.FAILED],
    JobStatus.EXPLOITING:       [JobStatus.AGGREGATING, JobStatus.FAILED],
    JobStatus.AGGREGATING:      [JobStatus.MEMORY_ENRICHING, JobStatus.SCORING,
                                  JobStatus.REPORTING, JobStatus.FAILED],
    JobStatus.MEMORY_ENRICHING: [JobStatus.SCORING, JobStatus.FAILED],
    JobStatus.SCORING:          [JobStatus.REPORTING, JobStatus.DONE, JobStatus.FAILED],
    JobStatus.REPORTING:        [JobStatus.DONE, JobStatus.FAILED],
    JobStatus.DONE:             [],
    JobStatus.FAILED:           [],
}


class ScanRequest(BaseModel):
    url: str
    tier: str = "Basic"
    auth: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = None

    @field_validator("url")
    @classmethod
    def url_must_be_http(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        if len(v) > 2048:
            raise ValueError("URL too long (max 2048 chars)")
        return v

    @field_validator("tier")
    @classmethod
    def valid_tier(cls, v: str) -> str:
        if v not in ("Basic", "Professional"):
            raise ValueError("tier must be 'Basic' or 'Professional'")
        return v


class JobRecord(BaseModel):
    id: str
    target_url: str
    status: str
    progress: int = 0
    tier: str = "Basic"
    idempotency_key: Optional[str] = None
    created_at: str
    updated_at: str


class StatusUpdate(BaseModel):
    job_id: str
    status: JobStatus
    progress: Optional[int] = None

    @field_validator("progress")
    @classmethod
    def clamp_progress(cls, v):
        if v is not None:
            return max(0, min(100, v))
        return v


class FindingRecord(BaseModel):
    job_id: str
    type: str
    severity: str
    target_url: Optional[str] = None
    param: Optional[str] = None
    payload: Optional[str] = None
    confidence: float = 0.5
    evidence: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, v: str) -> str:
        return v if v in {"Critical", "High", "Medium", "Low", "Info"} else "Medium"

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v) -> float:
        try:
            return max(0.0, min(1.0, float(v)))
        except (TypeError, ValueError):
            return 0.5


class LogRecord(BaseModel):
    job_id: str
    message: str
    level: str = "INFO"
    component: str = "system"
    tier: str = "Basic"


# ─────────────────────────────────────────────────────────────────────────────
# SCHEMA
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-8000;
PRAGMA temp_store=MEMORY;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS jobs (
    id               TEXT    PRIMARY KEY,
    target_url       TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'pending'
                             CHECK(status IN (
                               'pending','crawling','scanning','exploiting',
                               'aggregating','memory_enriching','scoring',
                               'reporting','done','failed'
                             )),
    progress         INTEGER NOT NULL DEFAULT 0
                             CHECK(progress BETWEEN 0 AND 100),
    tier             TEXT    NOT NULL DEFAULT 'Basic'
                             CHECK(tier IN ('Basic','Professional')),
    idempotency_key  TEXT    UNIQUE,
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_jobs_status   ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_idem_key ON jobs(idempotency_key);

CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     TEXT    NOT NULL,
    message    TEXT    NOT NULL,
    level      TEXT    NOT NULL DEFAULT 'INFO',
    component  TEXT    NOT NULL DEFAULT 'system',
    tier       TEXT    NOT NULL DEFAULT 'Basic',
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_logs_job_id ON logs(job_id, id);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      TEXT    NOT NULL,
    type        TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'Medium'
                        CHECK(severity IN ('Critical','High','Medium','Low','Info')),
    target_url  TEXT,
    param       TEXT,
    payload     TEXT,
    confidence  REAL    NOT NULL DEFAULT 0.5
                        CHECK(confidence BETWEEN 0.0 AND 1.0),
    evidence    TEXT,
    metadata    TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_job_id   ON findings(job_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS reports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     TEXT    NOT NULL UNIQUE,
    content    TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS idempotency (
    key        TEXT PRIMARY KEY,
    job_id     TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS circuit_state (
    host            TEXT    PRIMARY KEY,
    state           TEXT    NOT NULL DEFAULT 'closed'
                            CHECK(state IN ('closed','open','half_open')),
    failure_count   INTEGER NOT NULL DEFAULT 0,
    last_failure_at TEXT,
    opened_at       TEXT,
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS kv_store (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
"""


# ─────────────────────────────────────────────────────────────────────────────
# CIRCUIT BREAKER
# ─────────────────────────────────────────────────────────────────────────────

class CircuitBreaker:
    FAILURE_THRESHOLD = int(os.getenv("CIRCUIT_FAILURE_THRESHOLD", "5"))
    RESET_TIMEOUT_S   = int(os.getenv("CIRCUIT_RESET_TIMEOUT_S",   "60"))

    def __init__(self, db: "DatabaseManager"):
        self._db = db

    def is_allowed(self, host: str) -> bool:
        try:
            row = self._get(host)
            if not row:
                return True
            state = row["state"]
            if state == "closed":
                return True
            if state == "open":
                opened_at = row.get("opened_at") or row.get("updated_at")
                if opened_at:
                    elapsed = time.time() - datetime.fromisoformat(
                        opened_at.replace("Z", "+00:00").replace("+00:00", "")
                    ).timestamp()
                    if elapsed >= self.RESET_TIMEOUT_S:
                        self._set_state(host, "half_open")
                        return True
                return False
            return True  # half_open: allow probe
        except Exception as e:
            logger.error(f"[CB] is_allowed error for {host}: {e}")
            return True

    def record_success(self, host: str) -> None:
        try:
            self._upsert(host, "closed", 0)
        except Exception as e:
            logger.error(f"[CB] record_success error: {e}")

    def record_failure(self, host: str) -> None:
        try:
            row   = self._get(host)
            count = (row["failure_count"] if row else 0) + 1
            state = row["state"] if row else "closed"
            if count >= self.FAILURE_THRESHOLD and state != "open":
                state = "open"
            self._upsert(host, state, count)
        except Exception as e:
            logger.error(f"[CB] record_failure error: {e}")

    def get_state(self, host: str) -> str:
        try:
            row = self._get(host)
            return row["state"] if row else "closed"
        except Exception:
            return "closed"

    def _get(self, host: str) -> Optional[Dict]:
        with self._db._conn() as con:
            row = con.execute(
                "SELECT * FROM circuit_state WHERE host=?", (host,)
            ).fetchone()
            return dict(row) if row else None

    def _set_state(self, host: str, state: str) -> None:
        with self._db._conn() as con:
            con.execute(
                "UPDATE circuit_state SET state=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE host=?",
                (state, host),
            )

    def _upsert(self, host: str, state: str, failures: int) -> None:
        now       = datetime.now(timezone.utc).isoformat()
        opened_at = now if state == "open" else None
        with self._db._conn() as con:
            con.execute(
                """INSERT INTO circuit_state (host, state, failure_count, last_failure_at, opened_at)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(host) DO UPDATE SET
                     state=excluded.state,
                     failure_count=excluded.failure_count,
                     last_failure_at=excluded.last_failure_at,
                     opened_at=CASE WHEN excluded.state='open' THEN excluded.opened_at
                                    ELSE circuit_state.opened_at END,
                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')""",
                (host, state, failures, now, opened_at),
            )


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE MANAGER
# ─────────────────────────────────────────────────────────────────────────────

class DatabaseManager:

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock   = threading.Lock()
        self.circuit = CircuitBreaker(self)
        self.db      = self   # legacy compat alias

    @contextmanager
    def _conn(self):
        con = sqlite3.connect(self.db_path, check_same_thread=False, timeout=15)
        con.row_factory = sqlite3.Row
        try:
            con.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                PRAGMA synchronous=NORMAL;
                PRAGMA cache_size=-8000;
                PRAGMA busy_timeout=5000;
            """)
            yield con
            con.commit()
        except sqlite3.Error as e:
            con.rollback()
            logger.error(f"[DB] Transaction rolled back: {e}")
            raise
        finally:
            con.close()

    # ── Init ──────────────────────────────────────────────────────────────────

    def init_db(self) -> None:
        try:
            with self._conn() as con:
                con.executescript(_SCHEMA)
            logger.info("[DB] Schema verified / created")
        except Exception as e:
            logger.critical(f"[DB] Schema init failed: {e}")
            raise

    def reset_queues(self) -> None:
        try:
            with self._conn() as con:
                con.execute("DELETE FROM kv_store WHERE key LIKE 'queue:%'")
                con.execute("DELETE FROM kv_store WHERE key LIKE 'session:%'")
        except Exception as e:
            logger.error(f"[DB] reset_queues failed: {e}")

    # ── Job CRUD ──────────────────────────────────────────────────────────────

    def insert_job(
        self,
        job_id: str,
        url: str,
        status: str = "pending",
        progress: int = 0,
        tier: str = "Basic",
        idempotency_key: Optional[str] = None,
    ) -> bool:
        try:
            if idempotency_key:
                if self.get_job_by_idempotency_key(idempotency_key):
                    return False
            with self._conn() as con:
                con.execute(
                    "INSERT OR IGNORE INTO jobs (id,target_url,status,progress,tier,idempotency_key) VALUES (?,?,?,?,?,?)",
                    (job_id, url, status, progress, tier, idempotency_key),
                )
                if idempotency_key:
                    con.execute(
                        "INSERT OR IGNORE INTO idempotency (key,job_id) VALUES (?,?)",
                        (idempotency_key, job_id),
                    )
            return True
        except Exception as e:
            logger.error(f"[DB] insert_job failed for {job_id}: {e}")
            return False

    def get_job(self, job_id: str) -> Optional[Dict]:
        try:
            with self._conn() as con:
                row = con.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] get_job failed for {job_id}: {e}")
            return None

    def get_job_by_idempotency_key(self, key: str) -> Optional[Dict]:
        try:
            with self._conn() as con:
                row = con.execute(
                    "SELECT j.* FROM jobs j JOIN idempotency i ON j.id=i.job_id WHERE i.key=?",
                    (key,),
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] get_job_by_idempotency_key failed: {e}")
            return None

    def update_job(
        self,
        job_id: str,
        status: Optional[str] = None,
        progress: Optional[int] = None,
        force: bool = False,
    ) -> bool:
        if status is None and progress is None:
            return True
        try:
            for attempt in range(3):
                current = self.get_job(job_id)
                if not current:
                    return False
                if not force and status and status != current["status"]:
                    try:
                        cur_s   = JobStatus(current["status"])
                        new_s   = JobStatus(status)
                        allowed = _VALID_TRANSITIONS.get(cur_s, [])
                        if new_s not in allowed:
                            logger.warning(
                                f"[DB] Blocked transition {cur_s}→{new_s} for {job_id} (attempt {attempt+1})"
                            )
                            time.sleep(0.1)
                            continue
                    except ValueError:
                        pass  # unknown enum value — let it through
                break

            parts, params = [], []
            if status is not None:
                parts.append("status=?")
                params.append(status)
            if progress is not None:
                parts.append("progress=?")
                params.append(max(0, min(100, progress)))
            parts.append("updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')")
            params.append(job_id)
            with self._conn() as con:
                con.execute(f"UPDATE jobs SET {', '.join(parts)} WHERE id=?", params)
            return True
        except Exception as e:
            logger.error(f"[DB] update_job failed for {job_id}: {e}")
            return False

    def update_job_status(self, job_id: str, status: str, progress: int = 0) -> bool:
        """
        Alias for workers / orchestrator.
        progress defaults to 0 so 2-argument calls don't raise TypeError.
        Uses force=True to bypass state machine checks.
        """
        return self.update_job(job_id, status=status, progress=progress, force=True)

    def get_job_status(self, job_id: str) -> Optional[str]:
        """Return just the status string, or None if the job doesn't exist."""
        job = self.get_job(job_id)
        return job["status"] if job else None

    # ── Stale job recovery ────────────────────────────────────────────────────

    def get_stale_jobs(self, timeout_minutes: int = 30) -> List[Dict]:
        try:
            with self._conn() as con:
                rows = con.execute(
                    """SELECT * FROM jobs
                       WHERE status NOT IN ('done','failed')
                       AND updated_at < datetime('now', '-' || ? || ' minutes')""",
                    (timeout_minutes,),
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[DB] get_stale_jobs failed: {e}")
            return []

    def mark_job_stale(self, job_id: str, reason: str = "Timeout") -> bool:
        try:
            with self._conn() as con:
                con.execute(
                    "UPDATE jobs SET status='failed',progress=100,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
                    (job_id,),
                )
            self.add_log(job_id, f"[SYSTEM] Job failed: {reason}", level="WARNING")
            return True
        except Exception as e:
            logger.error(f"[DB] mark_job_stale failed for {job_id}: {e}")
            return False

    def recover_stale_jobs(self, timeout_minutes: int = 30) -> int:
        stale     = self.get_stale_jobs(timeout_minutes)
        recovered = sum(1 for j in stale if self.mark_job_stale(j["id"], "Crash recovery"))
        if recovered:
            logger.warning(f"[DB] Recovered {recovered} stale jobs")
        return recovered

    # ── Logs ──────────────────────────────────────────────────────────────────

    def add_log(
        self,
        job_id: str,
        message: str,
        level: str = "INFO",
        component: str = "system",
        tier: str = "Basic",
    ) -> None:
        try:
            with self._conn() as con:
                con.execute(
                    "INSERT INTO logs (job_id,message,level,component,tier) VALUES (?,?,?,?,?)",
                    (job_id, message, level, component, tier),
                )
        except Exception as e:
            print(f"[DB-LOG-FAIL] {e}: {message[:80]}")

    def save_error_log(self, job_id: str, message: str) -> None:
        """
        Persist a full error / stack-trace string so operators can inspect
        worker failures from the dashboard.
        """
        self.add_log(job_id, message[:4000], level="ERROR", component="worker_error")

    def get_logs(self, job_id: str, limit: int = 500) -> List[Dict]:
        try:
            with self._conn() as con:
                rows = con.execute(
                    "SELECT message,level,component,tier,created_at FROM logs WHERE job_id=? ORDER BY id DESC LIMIT ?",
                    (job_id, limit),
                ).fetchall()
                return [dict(r) for r in reversed(rows)]
        except Exception as e:
            logger.error(f"[DB] get_logs failed for {job_id}: {e}")
            return []

    def get_log_messages(self, job_id: str, limit: int = 500) -> List[str]:
        """
        Return JSON-encoded log strings in chronological order.

        Each string encodes:
          { message, time (HH:MM:SS), level, component, stage, tier }

        The `stage` field (component in uppercase) is what the JS log renderer
        uses as the coloured label — e.g. "[SCAN]", "[CRAWL]", "[EXPLOIT]".
        """
        try:
            with self._conn() as con:
                rows = con.execute(
                    "SELECT message,level,component,tier,created_at FROM logs WHERE job_id=? ORDER BY id DESC LIMIT ?",
                    (job_id, limit),
                ).fetchall()
                result = []
                for r in reversed(rows):
                    ts = r["created_at"] or ""
                    if "T" in ts:
                        ts = ts.split("T")[1][:8]
                    result.append(json.dumps({
                        "message":   r["message"],
                        "time":      ts,
                        "level":     r["level"],
                        "component": r["component"],
                        "stage":     r["component"].upper(),
                        "tier":      r["tier"],
                    }))
                return result
        except Exception as e:
            logger.error(f"[DB] get_log_messages failed: {e}")
            return []

    # ── Findings ──────────────────────────────────────────────────────────────

    def save_vulnerabilities(self, job_id: str, findings: List[Dict]) -> int:
        """
        Bulk-insert findings.  Normalises field names before validation so that
        findings from both scanner paths persist correctly.

        Field normalisations applied (FIX for Bug 4):
          "url"              → "target_url"   (ActiveScanner uses "url")
          "parameter"        → "param"        (ActiveScanner uses "parameter")
          "confidence_score" → "confidence"   (evidence-gated scan_worker)
          "evidence_snippet" → "evidence"     (evidence-gated scan_worker)
        """
        if not findings:
            return 0

        rows, skipped = [], 0
        for raw in findings:
            try:
                n = dict(raw)   # never mutate caller's dict

                # ── Field name normalisation ───────────────────────────────────
                if "url" in n and "target_url" not in n:
                    n["target_url"] = n.pop("url")

                if "parameter" in n and "param" not in n:
                    n["param"] = n.pop("parameter")

                if "confidence_score" in n:
                    if "confidence" not in n or n.get("confidence") in (None, 0.5):
                        n["confidence"] = n["confidence_score"]

                # evidence_snippet (new) takes priority over evidence (old)
                evidence = n.get("evidence_snippet") or n.get("evidence")

                # ── Validate ───────────────────────────────────────────────────
                f = FindingRecord(job_id=job_id, **{
                    k: v for k, v in n.items()
                    if k in FindingRecord.model_fields
                })

                rows.append((
                    f.job_id, f.type, f.severity,
                    f.target_url,
                    f.param,
                    f.payload,
                    f.confidence,
                    evidence or f.evidence,
                    json.dumps(f.metadata) if f.metadata else None,
                ))
            except Exception as e:
                skipped += 1
                logger.warning(f"[DB] Finding skipped (validation error): {e}")

        if not rows:
            return 0

        try:
            with self._conn() as con:
                con.executemany(
                    """INSERT INTO findings
                       (job_id,type,severity,target_url,param,payload,confidence,evidence,metadata)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    rows,
                )
            logger.info(f"[DB] Saved {len(rows)} findings for {job_id}" +
                        (f" ({skipped} skipped)" if skipped else ""))
            return len(rows)
        except Exception as e:
            logger.error(f"[DB] save_vulnerabilities failed: {e}")
            return 0

    def get_findings(self, job_id: str) -> List[Dict]:
        try:
            with self._conn() as con:
                rows = con.execute(
                    "SELECT * FROM findings WHERE job_id=? ORDER BY severity, id",
                    (job_id,),
                ).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    if d.get("metadata"):
                        try:
                            d["metadata"] = json.loads(d["metadata"])
                        except Exception:
                            pass
                    # Expose both field names the frontend may look for
                    d["confidence_score"] = d.get("confidence", 0.5)
                    result.append(d)
                return result
        except Exception as e:
            logger.error(f"[DB] get_findings failed for {job_id}: {e}")
            return []

    # ── Reports ───────────────────────────────────────────────────────────────

    def save_report(self, job_id: str, content: Any) -> bool:
        try:
            payload = json.dumps(content) if not isinstance(content, str) else content
            with self._conn() as con:
                con.execute(
                    "INSERT OR REPLACE INTO reports (job_id,content) VALUES (?,?)",
                    (job_id, payload),
                )
            return True
        except Exception as e:
            logger.error(f"[DB] save_report failed for {job_id}: {e}")
            return False

    def get_report(self, job_id: str) -> Optional[Dict]:
        try:
            with self._conn() as con:
                row = con.execute(
                    "SELECT content FROM reports WHERE job_id=?", (job_id,)
                ).fetchone()
                if not row:
                    return None
                data = json.loads(row["content"])
                return data if isinstance(data, dict) else {"content": str(data)}
        except Exception as e:
            logger.error(f"[DB] get_report failed for {job_id}: {e}")
            return None

    # ── KV Store ──────────────────────────────────────────────────────────────

    def kv_set(self, key: str, value: str) -> None:
        try:
            with self._conn() as con:
                con.execute(
                    "INSERT OR REPLACE INTO kv_store (key,value,updated_at) VALUES (?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    (key, value),
                )
        except Exception as e:
            logger.error(f"[DB] kv_set failed for {key!r}: {e}")

    def kv_get(self, key: str) -> Optional[str]:
        try:
            with self._conn() as con:
                row = con.execute("SELECT value FROM kv_store WHERE key=?", (key,)).fetchone()
                return row["value"] if row else None
        except Exception as e:
            logger.error(f"[DB] kv_get failed for {key!r}: {e}")
            return None

    def kv_delete(self, key: str) -> None:
        try:
            with self._conn() as con:
                con.execute("DELETE FROM kv_store WHERE key=?", (key,))
        except Exception as e:
            logger.error(f"[DB] kv_delete failed for {key!r}: {e}")

    def kv_incr(self, key: str, by: int = 1) -> int:
        try:
            with self._conn() as con:
                row     = con.execute("SELECT value FROM kv_store WHERE key=?", (key,)).fetchone()
                new_val = (int(row["value"]) if row else 0) + by
                con.execute(
                    "INSERT OR REPLACE INTO kv_store (key,value,updated_at) VALUES (?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    (key, str(new_val)),
                )
                return new_val
        except Exception as e:
            logger.error(f"[DB] kv_incr failed for {key!r}: {e}")
            return 0

    # ── Composite status query ────────────────────────────────────────────────

    def get_job_full_status(self, job_id: str) -> Optional[Dict]:
        try:
            job = self.get_job(job_id)
            if not job:
                return None
            logs     = self.get_log_messages(job_id)
            findings = self.get_findings(job_id)
            report   = self.get_report(job_id)
            crits    = sum(1 for f in findings if f.get("severity") == "Critical")
            return {
                "job_id":         job_id,
                "status":         job["status"],
                "progress":       job["progress"],
                "tier":           job["tier"],
                "target_url":     job["target_url"],
                "completed":      job["status"] in ("done", "failed"),
                "created_at":     job["created_at"],
                "updated_at":     job["updated_at"],
                "logs":           logs,
                "findings":       findings,
                "finding_count":  len(findings),
                "critical_count": crits,
                "report":         report,
            }
        except Exception as e:
            logger.error(f"[DB] get_job_full_status failed for {job_id}: {e}")
            return None

    # ── Taint analysis ────────────────────────────────────────────────────────

    def record_taint_hit(self, job_id: str, param: str, sink: str, payload: str, url: str) -> None:
        self.save_vulnerabilities(job_id, [{
            "type":       f"Taint: unsanitised input → {sink}",
            "severity":   "High",
            "target_url": url,
            "param":      param,
            "payload":    payload,
            "confidence": 0.85,
            "evidence":   f"Payload reached {sink} without sanitization",
            "metadata":   {"sink": sink, "analysis": "taint"},
        }])
        self.add_log(job_id, f"[TAINT] {param} → {sink} @ {url[:60]}", level="WARNING", component="taint_engine")


# ─────────────────────────────────────────────────────────────────────────────
# SINGLETON
# ─────────────────────────────────────────────────────────────────────────────

_db_instance: Optional[DatabaseManager] = None


def get_db(db_path: str = DB_PATH) -> DatabaseManager:
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseManager(db_path)
    return _db_instance

