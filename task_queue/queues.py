# task_queue/queues.py
# FIX: Added MEMORY_QUEUE and SCORING_QUEUE that core/pipeline.py imports

CRAWL_QUEUE       = "crawl_queue"
SCAN_QUEUE        = "scan_queue"
BROWSER_QUEUE     = "browser_queue"
SAST_QUEUE        = "sast_queue"
EXPLOIT_QUEUE     = "exploit_queue"
AGGREGATION_QUEUE = "aggregation_queue"
REPORT_QUEUE      = "report_queue"
NETWORK_QUEUE     = "network_queue"
MOBILE_QUEUE      = "mobile_queue"
API_QUEUE         = "api_queue"
PLANNER_QUEUE     = "planner_queue"
MEMORY_QUEUE      = "memory_queue"
SCORING_QUEUE     = "scoring_queue"
AUTH_QUEUE        = "auth_queue"