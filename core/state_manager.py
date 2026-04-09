import redis
import json

import os
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


class StateManager:
    def _key(self, job_id):
        return f"job_state:{job_id}"

    def init_job(self, job_id, scan_type):
        state = {
            "scan_type": scan_type,
            "stages": {
                "crawl": "pending",
                "sast": "pending",
                "scan": "pending",
                "exploit": "pending",
                "aggregation": "pending",
                "report": "pending",
            }
        }
        r.set(self._key(job_id), json.dumps(state))

    def mark_done(self, job_id, stage):
        state = json.loads(r.get(self._key(job_id)))
        state["stages"][stage] = "done"
        r.set(self._key(job_id), json.dumps(state))

    def is_complete(self, job_id):
        state = json.loads(r.get(self._key(job_id)))
        stages = state["stages"]

        # define completion rules
        required = ["scan", "exploit", "aggregation"]

        return all(stages[s] == "done" for s in required)