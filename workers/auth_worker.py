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

    creds = job.get("auth")

    if not creds:
        # no auth → go straight to crawl
        on_crawl_complete(job_id, [url])
        return

    push_log(job_id, "[AUTH] Logging in")

    session = auth.login(
        creds["login_url"],
        creds["username"],
        creds["password"]
    )

    if not session:
        push_log(job_id, "[AUTH] Failed")
        on_crawl_complete(job_id, [url])
        return

    save_session(job_id, session)

    push_log(job_id, "[AUTH] Success")

    on_crawl_complete(job_id, [url], auth=session)


if __name__ == "__main__":
    worker_loop(AUTH_QUEUE, handle)