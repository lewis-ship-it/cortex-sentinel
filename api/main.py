import asyncio
import json
import logging
import os
import sqlite3
import time
import traceback
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, field_validator

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("sentinel")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

DB_PATH  = os.getenv("DB_PATH",          "sentinel.db")
API_KEY  = os.getenv("SENTINEL_API_KEY", "test-key-123")
PORT     = int(os.getenv("PORT",         "8000"))

# ── Optional worker / queue layer ─────────────────────────────────────────────
_HAS_QUEUE = False
try:
    from task_queue.redis_scanner import enqueue_scan as _enqueue
    from task_queue.redis_client  import push as _push, clear_queues as _clear
    _HAS_QUEUE = True
    logger.info("✅  Redis queue detected — jobs will reach workers")
except Exception as _qe:
    logger.warning(f"⚠️   Queue layer not found ({_qe}) — DB-only mode")
    def _enqueue(d): pass
    def _push(q, d): pass
    def _clear():    pass

def enqueue_scan(d): _enqueue(d)
def push(q, d):      _push(q, d)
def clear_queues():  _clear()

# ─────────────────────────────────────────────────────────────────────────────
# MINIMAL SQLITE LAYER
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS jobs (
    id              TEXT PRIMARY KEY,
    target_url      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    progress        INTEGER NOT NULL DEFAULT 0,
    tier            TEXT NOT NULL DEFAULT 'Basic',
    idempotency_key TEXT UNIQUE,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     TEXT NOT NULL,
    message    TEXT NOT NULL,
    level      TEXT NOT NULL DEFAULT 'INFO',
    component  TEXT NOT NULL DEFAULT 'system',
    tier       TEXT NOT NULL DEFAULT 'Basic',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_logs_job ON logs(job_id, id);

CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     TEXT NOT NULL,
    type       TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'Medium',
    target_url TEXT,
    param      TEXT,
    payload    TEXT,
    confidence REAL NOT NULL DEFAULT 0.5,
    evidence   TEXT,
    metadata   TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(job_id);

CREATE TABLE IF NOT EXISTS reports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     TEXT NOT NULL UNIQUE,
    content    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS idempotency (
    key    TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS kv_store (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
"""


class _MinimalDB:
    """Minimal SQLite persistence — used when core.database isn't importable."""

    def __init__(self, path: str = DB_PATH):
        self.db_path = path

    @contextmanager
    def _conn(self):
        con = sqlite3.connect(self.db_path, check_same_thread=False, timeout=15)
        con.row_factory = sqlite3.Row
        try:
            con.executescript(
                "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;"
            )
            yield con
            con.commit()
        except sqlite3.Error as e:
            con.rollback()
            logger.error(f"[DB] rolled back: {e}")
            raise
        finally:
            con.close()

    def init_db(self):
        with self._conn() as c:
            c.executescript(_SCHEMA)
        logger.info(f"[DB] schema ready → {self.db_path}")

    # alias used by lifespan
    init = init_db

    def reset_queues(self):
        try:
            with self._conn() as c:
                c.execute("DELETE FROM kv_store WHERE key LIKE 'queue:%'")
        except Exception as e:
            logger.warning(f"[DB] reset_queues: {e}")

    # ── Jobs ──────────────────────────────────────────────────────────────────

    def insert_job(self, job_id, url, status="pending", tier="Basic",
                   idempotency_key=None, **_) -> bool:
        try:
            if idempotency_key and self.get_job_by_idempotency_key(idempotency_key):
                return False
            with self._conn() as c:
                c.execute(
                    "INSERT OR IGNORE INTO jobs (id,target_url,status,tier,idempotency_key)"
                    " VALUES (?,?,?,?,?)",
                    (job_id, url, status, tier, idempotency_key),
                )
                if idempotency_key:
                    c.execute(
                        "INSERT OR IGNORE INTO idempotency (key,job_id) VALUES (?,?)",
                        (idempotency_key, job_id),
                    )
            return True
        except Exception as e:
            logger.error(f"[DB] insert_job: {e}")
            return False

    def get_job(self, job_id) -> Optional[Dict]:
        try:
            with self._conn() as c:
                row = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] get_job: {e}")
            return None

    def get_job_by_idempotency_key(self, key) -> Optional[Dict]:
        try:
            with self._conn() as c:
                row = c.execute(
                    "SELECT j.* FROM jobs j JOIN idempotency i ON j.id=i.job_id WHERE i.key=?",
                    (key,),
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] get_job_by_idem: {e}")
            return None

    def update_job(self, job_id, status=None, progress=None, **_):
        parts, params = [], []
        if status   is not None:
            parts.append("status=?")
            params.append(status)
        if progress is not None:
            parts.append("progress=?")
            params.append(max(0, min(100, int(progress))))
        if not parts:
            return True
        parts.append("updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')")
        params.append(job_id)
        try:
            with self._conn() as c:
                c.execute(f"UPDATE jobs SET {', '.join(parts)} WHERE id=?", params)
            return True
        except Exception as e:
            logger.error(f"[DB] update_job: {e}")
            return False

    def get_job_status(self, job_id) -> Optional[str]:
        """Return just the status string, or None if the job doesn't exist."""
        job = self.get_job(job_id)
        return job["status"] if job else None

    def list_jobs(self, limit=50) -> List[Dict]:
        try:
            with self._conn() as c:
                return [dict(r) for r in c.execute(
                    "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()]
        except Exception as e:
            logger.error(f"[DB] list_jobs: {e}")
            return []

    # ── Logs ──────────────────────────────────────────────────────────────────

    def add_log(self, job_id, message, level="INFO", component="system", tier="Basic"):
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO logs (job_id,message,level,component,tier) VALUES (?,?,?,?,?)",
                    (job_id, message, level, component, tier),
                )
        except Exception as e:
            print(f"[DB-LOG-FAIL] {e}")

    def get_log_messages(self, job_id, limit=500) -> List[str]:
        try:
            with self._conn() as c:
                rows = c.execute(
                    "SELECT message,level,component,tier,created_at"
                    " FROM logs WHERE job_id=? ORDER BY id DESC LIMIT ?",
                    (job_id, limit),
                ).fetchall()
                result = []
                for r in reversed(rows):
                    ts = (r["created_at"] or "")
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
            logger.error(f"[DB] get_log_messages: {e}")
            return []

    # ── Findings ──────────────────────────────────────────────────────────────

    def save_vulnerabilities(self, job_id, findings: List[Dict]) -> int:
        if not findings:
            return 0
        rows = []
        for raw in findings:
            n = dict(raw)
            if "url"       in n and "target_url" not in n:
                n["target_url"] = n.pop("url")
            if "parameter" in n and "param"      not in n:
                n["param"]      = n.pop("parameter")
            if "confidence_score" in n:
                n["confidence"] = n.get("confidence_score")
            evidence = n.get("evidence_snippet") or n.get("evidence", "")
            try:
                conf = max(0.0, min(1.0, float(n.get("confidence", 0.5) or 0.5)))
            except Exception:
                conf = 0.5
            rows.append((job_id, str(n.get("type","Unknown")), str(n.get("severity","Medium")),
                         n.get("target_url"), n.get("param"), n.get("payload"), conf, evidence,
                         json.dumps(n.get("metadata")) if n.get("metadata") else None))
        try:
            with self._conn() as c:
                c.executemany(
                    "INSERT INTO findings"
                    " (job_id,type,severity,target_url,param,payload,confidence,evidence,metadata)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    rows,
                )
            return len(rows)
        except Exception as e:
            logger.error(f"[DB] save_vulnerabilities: {e}")
            return 0

    def get_findings(self, job_id) -> List[Dict]:
        try:
            with self._conn() as c:
                rows = c.execute(
                    "SELECT * FROM findings WHERE job_id=? ORDER BY severity,id",
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
                    d["confidence_score"] = d.get("confidence", 0.5)
                    result.append(d)
                return result
        except Exception as e:
            logger.error(f"[DB] get_findings: {e}")
            return []

    # ── Reports ───────────────────────────────────────────────────────────────

    def save_report(self, job_id, content):
        try:
            payload = json.dumps(content) if not isinstance(content, str) else content
            with self._conn() as c:
                c.execute("INSERT OR REPLACE INTO reports (job_id,content) VALUES (?,?)",
                          (job_id, payload))
        except Exception as e:
            logger.error(f"[DB] save_report: {e}")

    def get_report(self, job_id) -> Optional[Dict]:
        try:
            with self._conn() as c:
                row = c.execute(
                    "SELECT content FROM reports WHERE job_id=?", (job_id,)
                ).fetchone()
                if not row:
                    return None
                data = json.loads(row["content"])
                return data if isinstance(data, dict) else {"content": str(data)}
        except Exception as e:
            logger.error(f"[DB] get_report: {e}")
            return None

    # ── Composite ─────────────────────────────────────────────────────────────

    def get_job_full_status(self, job_id) -> Optional[Dict]:
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
            "completed":      job["status"] in ("done","failed"),
            "created_at":     job["created_at"],
            "updated_at":     job["updated_at"],
            "logs":           logs,
            "findings":       findings,
            "finding_count":  len(findings),
            "critical_count": crits,
            "report":         report,
        }

    # ── KV ────────────────────────────────────────────────────────────────────

    def kv_set(self, key, value):
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT OR REPLACE INTO kv_store (key,value,updated_at)"
                    " VALUES (?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    (key, value),
                )
        except Exception as e:
            logger.error(f"[DB] kv_set: {e}")

    def kv_get(self, key) -> Optional[str]:
        try:
            with self._conn() as c:
                row = c.execute("SELECT value FROM kv_store WHERE key=?", (key,)).fetchone()
                return row["value"] if row else None
        except Exception as e:
            logger.error(f"[DB] kv_get: {e}")
            return None

    def save_error_log(self, job_id, message):
        self.add_log(job_id, message[:4000], level="ERROR", component="worker_error")


# ── Singleton factory ─────────────────────────────────────────────────────────

_db_instance = None

def get_db():
    global _db_instance
    if _db_instance is not None:
        return _db_instance
    try:
        from core.database import get_db as _proj_get_db
        _db_instance = _proj_get_db()
        logger.info("✅  Using full project DatabaseManager")
    except Exception:
        _db_instance = _MinimalDB(DB_PATH)
        logger.info("ℹ   Using built-in minimal DB")
    return _db_instance


# ─────────────────────────────────────────────────────────────────────────────
# SAFETY GUARD  (inline)
# ─────────────────────────────────────────────────────────────────────────────

_BLOCKED = {
    "paypal.com","login.microsoft.com","facebook.com",
    "google.com","apple.com","amazon.com","chase.com","bankofamerica.com",
}

def _is_safe(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        h = urlparse(url).netloc.lower()
        if h.startswith("www."):
            h = h[4:]
        return h not in _BLOCKED
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITER  (simple in-memory)
# ─────────────────────────────────────────────────────────────────────────────

_hits: Dict[str, List[float]] = {}

def _rate_ok(key: str, limit: int = 30) -> bool:
    now = time.time()
    h   = [t for t in _hits.get(key, []) if now - t < 60]
    if len(h) >= limit:
        return False
    h.append(now)
    _hits[key] = h
    return True


# ─────────────────────────────────────────────────────────────────────────────
# NORMALISATION HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _norm_logs(raw: List) -> List[Dict]:
    out = []
    for entry in raw:
        # FIX: variable shadowing bug — the loop variable was named `e` and the
        # except clause also used `e` as both the exception AND the reassigned
        # dict. On json.loads failure, `e` held the Exception object, which was
        # then passed to `e.get(...)` below, causing an AttributeError.
        # Renamed loop variable to `entry` and exception to `exc` throughout.
        if isinstance(entry, str):
            try:
                entry = json.loads(entry)
            except Exception as exc:
                entry = {"message": str(exc)}
        if not isinstance(entry, dict):
            entry = {"message": str(entry)}
        ts = entry.get("time") or entry.get("timestamp") or entry.get("created_at","")
        if ts and "T" in ts:
            ts = ts.split("T")[1][:8]
        comp = entry.get("component") or entry.get("tier") or "system"
        out.append({
            "message":   entry.get("message",""),
            "time":      ts,
            "timestamp": ts,
            "level":     entry.get("level","INFO"),
            "component": comp,
            "stage":     (entry.get("stage") or comp).upper(),
        })
    return out


def _norm_findings(raw: List[Dict]) -> List[Dict]:
    out = []
    for f in raw:
        if not isinstance(f, dict):
            continue
        conf = f.get("confidence_score") or f.get("confidence") or 0.0
        f["confidence"] = f["confidence_score"] = conf
        if not f.get("target_url") and f.get("url"):
            f["target_url"] = f["url"]
        out.append(f)
    return out


def _norm_report(r) -> Optional[Dict]:
    if r is None:
        return None
    if not isinstance(r, dict):
        return {"content": str(r)}
    if r.get("content"):
        return r
    parts = []
    if r.get("executive_summary"):
        parts.append(f"EXECUTIVE SUMMARY\n{'─'*44}\n{r['executive_summary']}\n")
    if isinstance(r.get("summary"), dict):
        parts.append("SCAN SUMMARY\n" + "─"*44)
        for k, v in r["summary"].items():
            parts.append(f"  {k.replace('_',' ').title()}: {v}")
        parts.append("")
    fl = r.get("findings",[])
    if fl:
        parts.append(f"FINDINGS ({len(fl)} total)\n" + "─"*44)
        for i, f in enumerate(fl[:30],1):
            parts.append(f"  [{i:02d}] [{f.get('severity','?'):<8}] {f.get('type','?')}  param={f.get('param','-')}")
        if len(fl)>30:
            parts.append(f"  … and {len(fl)-30} more")
    r = dict(r)
    r["content"] = "\n".join(parts) if parts else json.dumps(r, indent=2)
    return r


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD HTML LOADER
# ─────────────────────────────────────────────────────────────────────────────

def _load_dashboard() -> str:
    here = Path(__file__).parent
    for p in [here/"index.html", here/"templates"/"index.html",
              Path("index.html"), Path("templates")/"index.html"]:
        if p.exists():
            try:
                return p.read_text(encoding="utf-8")
            except Exception:
                pass
    return """<!DOCTYPE html>
<html>
<head><title>Cortex Sentinel</title>
<style>
body{background:#050810;color:#c9d1d9;font-family:'Segoe UI',sans-serif;
  display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#0d1117;border:1px solid #21262d;border-radius:8px;
  padding:40px;max-width:520px;text-align:center;line-height:1.7}
h2{color:#00f5c4;margin-bottom:12px;font-size:22px}
code{color:#58a6ff;background:#0d1117;padding:2px 6px;border-radius:3px}
a{color:#00f5c4}p{color:#8b949e;font-size:14px}
</style></head>
<body><div class="box">
<h2>⬡ Sentinel API is Online</h2>
<p>Dashboard HTML not found. Place <code>index.html</code> in the same
directory as <code>main.py</code> and reload this page.</p>
<p style="margin-top:20px">
  <a href="/docs">/docs</a> &nbsp;·&nbsp;
  <a href="/health">/health</a> &nbsp;·&nbsp;
  <a href="/api/jobs">/api/jobs</a>
</p>
</div></body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
# LIFESPAN
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    db = get_db()
    (getattr(db,"init_db",None) or getattr(db,"init",lambda:None))()
    if hasattr(db, "reset_queues"):
        db.reset_queues()
    try:
        clear_queues()
    except Exception as e:
        logger.warning(f"Queue clear: {e}")
    logger.info(f"🚀  Sentinel API ready  →  http://localhost:{PORT}")
    yield
    logger.info("🛑  Sentinel API shut down")


# ─────────────────────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Sentinel Scanner API",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

def verify_key(key: str = Security(api_key_header)) -> str:
    if not key or key != API_KEY:
        raise HTTPException(403, "Invalid or missing API key")
    return key


class ScanIn(BaseModel):
    url: str
    tier: str = "Basic"
    auth: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = None

    @field_validator("url")
    @classmethod
    def chk_url(cls, v):
        v = v.strip()
        if not v.startswith(("http://","https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    @field_validator("tier")
    @classmethod
    def chk_tier(cls, v):
        if v not in ("Basic","Professional"):
            raise ValueError("tier must be Basic or Professional")
        return v


class ScanOut(BaseModel):
    job_id: str
    type:   str
    idempotent: bool = False


@app.exception_handler(Exception)
async def _global_err(request: Request, exc: Exception):
    logger.error(f"[API] {request.method} {request.url}  →  {exc}\n{traceback.format_exc()}")
    return JSONResponse(status_code=500,
                        content={"detail": str(exc), "type": type(exc).__name__})


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def dashboard():
    return HTMLResponse(_load_dashboard())


@app.get("/health", tags=["System"])
def health():
    db = get_db()
    ok = False
    try:
        with db._conn() as c:
            c.execute("SELECT 1").fetchone()
            ok = True
    except Exception:
        pass
    return {"status":"ok" if ok else "degraded",
            "db":"sqlite:ok" if ok else "sqlite:error",
            "queue":"redis" if _HAS_QUEUE else "none",
            "timestamp": datetime.utcnow().isoformat()}


@app.post("/scan", response_model=ScanOut, tags=["Scanning"])
async def start_scan(req: ScanIn, key: str = Depends(verify_key)):
    if not _rate_ok(key):
        raise HTTPException(429, "Too many requests")
    if not _is_safe(req.url):
        raise HTTPException(403, "Target URL is not permitted")

    db = get_db()

    if req.idempotency_key:
        fn = getattr(db,"get_job_by_idempotency_key", getattr(db,"get_job_by_idem",None))
        if fn:
            ex = fn(req.idempotency_key)
            if ex:
                return ScanOut(job_id=ex["id"], type="web_scan", idempotent=True)

    job_id = str(uuid.uuid4())
    ok = db.insert_job(job_id=job_id, url=req.url, status="pending",
                       tier=req.tier, idempotency_key=req.idempotency_key)
    if not ok:
        raise HTTPException(500, "Failed to create job record")

    if hasattr(db,"add_log"):
        db.add_log(job_id, f"[API] Scan queued for {req.url}",
                   component="api", tier=req.tier)

    _crawl_payload = {
        "job_id":     job_id,
        "url":        req.url,
        "target_url": req.url,
        "tier":       req.tier,
        "auth":       req.auth,
    }
    if req.auth:
        push("auth_queue", _crawl_payload)
        logger.info(f"[API] Auth→Crawl pipeline started  job={job_id}  url={req.url[:70]}")
    else:
        enqueue_scan(_crawl_payload)
        logger.info(f"[API] Scan job queued  job={job_id}  url={req.url[:70]}")
    return ScanOut(job_id=job_id, type="web_scan")


@app.get("/api/status/{job_id}", tags=["Jobs"])
async def get_status(job_id: str):
    db  = get_db()
    fn  = getattr(db,"get_job_full_status", None)
    raw = fn(job_id) if fn else None
    if not raw:
        raise HTTPException(404, f"Job {job_id!r} not found")
    return {
        "job_id":         raw["job_id"],
        "status":         raw.get("status","unknown"),
        "progress":       raw.get("progress", 0),
        "tier":           raw.get("tier","Basic"),
        "target_url":     raw.get("target_url",""),
        "completed":      raw.get("completed", False),
        "created_at":     raw.get("created_at",""),
        "updated_at":     raw.get("updated_at",""),
        "logs":           _norm_logs(raw.get("logs",[])),
        "findings":       _norm_findings(raw.get("findings",[])),
        "report":         _norm_report(raw.get("report")),
        "finding_count":  raw.get("finding_count", 0),
        "critical_count": raw.get("critical_count", 0),
    }


@app.get("/job/{job_id}", tags=["Jobs"])
def job_legacy(job_id: str):
    j = get_db().get_job(job_id)
    if not j:
        raise HTTPException(404,"Job not found")
    return j


@app.get("/api/jobs", tags=["Jobs"])
def list_jobs():
    fn = getattr(get_db(),"list_jobs",None)
    return fn(50) if fn else []


@app.get("/logs/{job_id}", tags=["Jobs"])
def get_logs(job_id: str):
    fn = getattr(get_db(),"get_log_messages",None)
    return _norm_logs(fn(job_id) if fn else [])


@app.get("/findings/{job_id}", tags=["Jobs"])
def get_findings(job_id: str):
    fn = getattr(get_db(),"get_findings",None)
    return _norm_findings(fn(job_id) if fn else [])


@app.get("/report/{job_id}", tags=["Jobs"])
def get_report(job_id: str):
    fn = getattr(get_db(),"get_report",None)
    r  = fn(job_id) if fn else None
    if not r:
        raise HTTPException(404,"Report not available yet")
    return _norm_report(r)


@app.get("/api/stream/{job_id}", tags=["Realtime"])
async def stream(job_id: str):
    db = get_db()
    async def gen():
        sent = polls = 0
        fn_logs = getattr(db,"get_log_messages",None)
        fn_job  = getattr(db,"get_job",None)
        while polls < 600:
            polls += 1
            try:
                logs = _norm_logs(fn_logs(job_id,500) if fn_logs else [])
                for e in logs[sent:]:
                    yield f"data: {json.dumps(e)}\n\n"
                    sent += 1
                job = fn_job(job_id) if fn_job else None
                if not job:
                    yield f"data: {json.dumps({'type':'error','message':'Job not found'})}\n\n"
                    break
                if job["status"] in ("done","failed"):
                    yield f"data: {json.dumps({'type':'complete','status':job['status'],'message':'Scan finished'})}\n\n"
                    break
                await asyncio.sleep(1.0)
            except GeneratorExit:
                break
            except Exception as e:
                yield f"data: {json.dumps({'type':'error','message':str(e)})}\n\n"
                await asyncio.sleep(2.0)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","Connection":"keep-alive","X-Accel-Buffering":"no"})


@app.post("/api/admin/clear-queues", tags=["Admin"])
def admin_clear(key: str = Depends(verify_key)):
    try:
        clear_queues()
        db = get_db()
        if hasattr(db,"reset_queues"):
            db.reset_queues()
        return {"status":"ok"}
    except Exception as e:
        raise HTTPException(500,str(e))


@app.get("/api/admin/stats", tags=["Admin"])
def admin_stats(key: str = Depends(verify_key)):
    db = get_db()
    try:
        with db._conn() as c:
            j  = c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            jr = c.execute("SELECT COUNT(*) FROM jobs WHERE status NOT IN ('done','failed')").fetchone()[0]
            f  = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            lg = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        return {"jobs":j,"jobs_running":jr,"findings":f,"logs":lg,
                "db": getattr(db,"db_path", DB_PATH)}
    except Exception as e:
        raise HTTPException(500,str(e))


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=PORT,
                reload=True, log_level="info")