import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

MAX_URLS = 500
MAX_DEPTH = 5

STAGES = [
    "crawl",
    "scan",
    "exploit",
    "aggregation",
    "report"
]