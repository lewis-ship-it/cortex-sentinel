
import docker
import os
import json
import time
from datetime import datetime
from task_queue.redis_client import get_redis_connection

# Docker and Redis setup
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
client = docker.from_env()



redis_client = get_redis_connection()

# Container names to monitor (from docker-compose)
MONITORED_CONTAINERS = [
    "sentinel_scan_worker",
    "sentinel_report_worker",
    "sentinel_memory_worker",
    "sentinel_scoring_worker",
    "sentinel_dashboard",
]

LOG_STREAM_KEY = "container_logs"  # Redis stream key
MAX_LOGS_PER_CONTAINER = 1000  # Keep last N logs per container


def sanitize_log_line(line):
    """Clean up log line for JSON serialization"""
    if isinstance(line, bytes):
        line = line.decode('utf-8', errors='ignore')
    return line.strip()


def push_log_to_redis(container_name, log_line):
    """Push a single log entry to Redis stream"""
    if not redis_client:
        print(f"[ERROR] Redis not connected, skipping log push for {container_name}")
        return
    
    try:
        log_entry = {
            "container": container_name,
            "timestamp": datetime.utcnow().isoformat(),
            "message": sanitize_log_line(log_line),
        }
        
        # Add to Redis stream (auto-trims to MAX_LOGS_PER_CONTAINER)
        redis_client.xadd(
            f"{LOG_STREAM_KEY}:{container_name}",
            log_entry,
            maxlen=MAX_LOGS_PER_CONTAINER,
            approximate=True
        )
        
        # Also add to a general log stream for real-time dashboard updates
        redis_client.xadd(
            LOG_STREAM_KEY,
            log_entry,
            maxlen=5000,
            approximate=True
        )
    except Exception as e:
        print(f"[ERROR] Failed to push log: {e}")


def stream_container_logs(container_name):
    """Stream logs from a single container"""
    try:
        container = client.containers.get(container_name)
        print(f"[LOGGING WORKER] Streaming logs from {container_name}")
        
        # Get logs stream (follow=True means tail forever)
        for log_line in container.logs(stream=True, follow=True):
            push_log_to_redis(container_name, log_line)
    except docker.errors.NotFound:
        print(f"[WARNING] Container {container_name} not found, skipping...")
    except Exception as e:
        print(f"[ERROR] Error streaming {container_name}: {e}")


def monitor_containers():
    """Main loop: monitor all containers and stream their logs"""
    print("[LOGGING WORKER] Starting container log monitoring...")
    print(f"[LOGGING WORKER] Monitoring: {', '.join(MONITORED_CONTAINERS)}")
    
    # Start streaming logs from each container
    import threading
    threads = []
    
    for container_name in MONITORED_CONTAINERS:
        thread = threading.Thread(
            target=stream_container_logs,
            args=(container_name,),
            daemon=True
        )
        thread.start()
        threads.append(thread)
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[LOGGING WORKER] Shutting down...")


if __name__ == "__main__":
    monitor_containers()

