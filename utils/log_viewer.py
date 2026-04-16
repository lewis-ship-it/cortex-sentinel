"""
Dashboard helper module to query logs from Redis streams.
Use this in your Streamlit dashboard to fetch and display container logs.
"""

import os
from task_queue.redis_client import get_redis_connection

redis_client = get_redis_connection()


def get_container_logs(container_name, limit=100):
    """
    Fetch recent logs for a specific container.
    
    Args:
        container_name: Name of container (e.g., 'sentinel_scan_worker')
        limit: Number of recent logs to return
    
    Returns:
        List of log entries with timestamp and message
    """
    if not redis_client:
        return []
    
    try:
        stream_key = f"container_logs:{container_name}"
        logs = redis_client.xrevrange(stream_key, count=limit)
        
        # Convert Redis stream format to list of dicts
        result = []
        for entry_id, entry_data in logs:
            result.append({
                "id": entry_id.decode() if isinstance(entry_id, bytes) else entry_id,
                "timestamp": entry_data.get(b"timestamp", b"").decode(),
                "message": entry_data.get(b"message", b"").decode(),
            })
        
        return list(reversed(result))  # Reverse to show oldest first
    except Exception as e:
        print(f"[ERROR] Failed to fetch logs for {container_name}: {e}")
        return []


def get_all_logs(limit=500):
    """
    Fetch recent logs from all containers (general log stream).
    
    Args:
        limit: Number of recent logs to return
    
    Returns:
        List of log entries with container name, timestamp, and message
    """
    if not redis_client:
        return []
    
    try:
        stream_key = "container_logs"
        logs = redis_client.xrevrange(stream_key, count=limit)
        
        result = []
        for entry_id, entry_data in logs:
            result.append({
                "id": entry_id.decode() if isinstance(entry_id, bytes) else entry_id,
                "container": entry_data.get(b"container", b"unknown").decode(),
                "timestamp": entry_data.get(b"timestamp", b"").decode(),
                "message": entry_data.get(b"message", b"").decode(),
            })
        
        return list(reversed(result))  # Reverse to show oldest first
    except Exception as e:
        print(f"[ERROR] Failed to fetch all logs: {e}")
        return []


def get_logs_since(container_name, entry_id, limit=100):
    """
    Fetch logs since a specific entry ID (for live streaming).
    
    Args:
        container_name: Name of container
        entry_id: Redis stream entry ID to start from
        limit: Number of logs to return
    
    Returns:
        List of newer log entries
    """
    if not redis_client:
        return []
    
    try:
        stream_key = f"container_logs:{container_name}"
        # Use XRANGE to get logs after the given ID
        logs = redis_client.xrange(stream_key, min=f"({entry_id}", count=limit)
        
        result = []
        for entry_id, entry_data in logs:
            result.append({
                "id": entry_id.decode() if isinstance(entry_id, bytes) else entry_id,
                "timestamp": entry_data.get(b"timestamp", b"").decode(),
                "message": entry_data.get(b"message", b"").decode(),
            })
        
        return result
    except Exception as e:
        print(f"[ERROR] Failed to fetch logs since {entry_id}: {e}")
        return []
