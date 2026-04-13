# core/state_manager.py
import os, json, redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


class StateManager:
    def _key(self, job_id): return f"job_state:{job_id}"

    def init_job(self, job_id, scan_type):
        state = {
            "scan_type": scan_type,
            "stages": {
                "crawl": "pending", "scan": "pending",
                "exploit": "pending", "aggregation": "pending",
                "report": "pending",
            }
        }
        r.set(self._key(job_id), json.dumps(state), ex=86400)

    def mark_done(self, job_id, stage):
        raw = r.get(self._key(job_id))
        if not raw: return
        state = json.loads(raw)
        if stage in state["stages"]:
            state["stages"][stage] = "done"
        r.set(self._key(job_id), json.dumps(state), ex=86400)

    def is_complete(self, job_id):
        raw = r.get(self._key(job_id))
        if not raw: return False
        stages = json.loads(raw)["stages"]
        return all(stages.get(s) == "done" for s in ["scan", "aggregation"])
