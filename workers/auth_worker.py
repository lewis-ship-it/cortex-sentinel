# workers/auth_worker.py

from workers.base_worker import worker_loop, push_log
from task_queue.queues import AUTH_QUEUE
from core.session_store import save_session
from scanner.auth import Authenticator
from core.pipeline import on_crawl_complete

auth = Authenticator()

def handle(job):
    job_id = job["job_id"]
    url = job["url"]
    tier = job.get("tier", "Basic") # From base_worker fetch
    creds = job.get("auth")

    if not creds:
        # No auth provided -> Proceed to crawl immediately
        on_crawl_complete(job_id, [url])
        return

    push_log(job_id, f"[AUTH] Attempting login in {tier} mode", tier=tier)

    # PRODUCTION MOVE: We pass the tier to the authenticator. 
    # For Professional, it can handle sophisticated token refreshes or MFA bypasses.
    session = auth.login(
        creds["login_url"],
        creds["username"],
        creds["password"],
        tier=tier
    )

    if not session:
        push_log(job_id, "[AUTH] Login failed. Proceeding as unauthenticated.", tier=tier)
        on_crawl_complete(job_id, [url])
        return

    save_session(job_id, session)
    push_log(job_id, "[AUTH] Login successful. Session saved.", tier=tier)

    # Hand off to the next stage with the authenticated session
    on_crawl_complete(job_id, [url], auth=session)

if __name__ == "__main__":
    worker_loop(AUTH_QUEUE, handle)