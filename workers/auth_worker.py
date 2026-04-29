# workers/auth_worker.py
# ──────────────────────────────────────────────────────────────────────────────
# FIX — tier not propagated to on_crawl_complete()
#   Old code called on_crawl_complete(job_id, [url]) without passing tier.
#   pipeline.on_crawl_complete() defaults tier to "Basic" when omitted, so
#   every auth-gated Professional scan was silently downgraded to Basic tier,
#   causing it to receive limited crawl depth, no AI report, and no scoring.
#
#   Fixed: tier is now always passed to on_crawl_complete() in all call sites.
# ──────────────────────────────────────────────────────────────────────────────

from workers.base_worker import worker_loop, push_log
from task_queue.queues import AUTH_QUEUE
from core.session_store import save_session
from scanner.auth import Authenticator
from core.pipeline import on_crawl_complete

auth = Authenticator()


def handle(job: dict) -> None:
    job_id = job["job_id"]
    url    = job.get("url") or job.get("target_url")
    tier   = job.get("tier", "Basic")
    creds  = job.get("auth")

    if not url:
        push_log(job_id, "[AUTH] Job missing URL — skipping", tier=tier)
        return

    if not creds:
        # No auth provided → proceed to crawl immediately
        push_log(job_id, "[AUTH] No credentials provided — proceeding unauthenticated", tier=tier)
        on_crawl_complete(job_id, [url], auth=None, tier=tier)  # FIX: tier passed
        return

    push_log(job_id, f"[AUTH] Attempting login in {tier} mode", tier=tier)

    session = auth.login(
        creds["login_url"],
        creds["username"],
        creds["password"],
        tier=tier,
    )

    if not session:
        push_log(job_id, "[AUTH] Login failed — proceeding as unauthenticated", tier=tier)
        on_crawl_complete(job_id, [url], auth=None, tier=tier)  # FIX: tier passed
        return

    save_session(job_id, session)
    push_log(job_id, "[AUTH] Login successful. Session saved.", tier=tier)

    # Hand off to crawl with the authenticated session
    on_crawl_complete(job_id, [url], auth=session, tier=tier)  # FIX: tier passed


if __name__ == "__main__":
    worker_loop(AUTH_QUEUE, handle)