
"""
core/logger.py

Centralized structured logging for the entire system.
All workers and components use this for consistent log format.
"""

import json
import logging
import os
import redis
from typing import Optional, Dict, Any
from datetime import datetime

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Logging levels
class LogLevel:
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class StructuredLogEntry:
    """Represents a single structured log entry."""
    
    def __init__(
        self,
        timestamp: str,
        level: str,
        component: str,
        job_id: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        tier: str = "Basic"
    ):
        self.timestamp = timestamp
        self.level = level
        self.component = component
        self.job_id = job_id
        self.message = message
        self.details = details or {}
        self.tier = tier
    
    def to_dict(self) -> Dict:
        """Convert to dict for JSON serialization."""
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "component": self.component,
            "job_id": self.job_id,
            "message": self.message,
            "details": self.details,
            "tier": self.tier
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class SystemLogger:
    """
    Centralized logger that writes to:
    1. Python logging (console/files)
    2. Redis (for dashboard and real-time viewing)
    3. Structured format for easy parsing
    """
    
    def __init__(self, redis_url: str = REDIS_URL, component: str = "system"):
        self.redis_url = redis_url
        self.component = component
        self.r = redis.Redis.from_url(redis_url, decode_responses=True)
        
        # Setup Python logging
        self.logger = logging.getLogger(component)
        self.logger.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_format = logging.Formatter(
            '[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
    
    def _log_to_redis(self, entry: StructuredLogEntry):
        """Write log entry to Redis."""
        try:
            key = f"logs:{entry.job_id}"
            
            # Add to Redis list
            self.r.rpush(key, entry.to_json())
            
            # Keep only last 500 entries per job
            self.r.ltrim(key, -500, -1)
            
            # Set TTL (24 hours)
            self.r.expire(key, 86400)
            
            # Also add to global log index
            global_key = "logs:all"
            self.r.rpush(global_key, entry.to_json())
            self.r.ltrim(global_key, -10000, -1)
            self.r.expire(global_key, 86400)
            
        except Exception as e:
            self.logger.error(f"Failed to log to Redis: {e}")
    
    def log(
        self,
        level: str,
        message: str,
        job_id: str,
        details: Optional[Dict[str, Any]] = None,
        tier: str = "Basic"
    ):
        """
        Log a message with full context.
        
        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            message: Log message
            job_id: Associated job ID
            details: Optional additional details dict
            tier: User tier (Basic, Professional)
        """
        timestamp = datetime.utcnow().isoformat()
        
        # Create structured entry
        entry = StructuredLogEntry(
            timestamp=timestamp,
            level=level,
            component=self.component,
            job_id=job_id,
            message=message,
            details=details,
            tier=tier
        )
        
        # Log to Python logging
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(f"[{job_id}] {message}")
        
        # Log to Redis
        self._log_to_redis(entry)
    
    def debug(self, message: str, job_id: str, details: Optional[Dict] = None, tier: str = "Basic"):
        """Log debug message."""
        self.log(LogLevel.DEBUG, message, job_id, details, tier)
    
    def info(self, message: str, job_id: str, details: Optional[Dict] = None, tier: str = "Basic"):
        """Log info message."""
        self.log(LogLevel.INFO, message, job_id, details, tier)
    
    def warning(self, message: str, job_id: str, details: Optional[Dict] = None, tier: str = "Basic"):
        """Log warning message."""
        self.log(LogLevel.WARNING, message, job_id, details, tier)
    
    def error(self, message: str, job_id: str, details: Optional[Dict] = None, tier: str = "Basic"):
        """Log error message."""
        self.log(LogLevel.ERROR, message, job_id, details, tier)
    
    def critical(self, message: str, job_id: str, details: Optional[Dict] = None, tier: str = "Basic"):
        """Log critical message."""
        self.log(LogLevel.CRITICAL, message, job_id, details, tier)
    
    def get_job_logs(self, job_id: str, limit: int = 100) -> list[Dict]:
        """
        Retrieve logs for a specific job.
        
        Args:
            job_id: Job ID
            limit: Max logs to retrieve
            
        Returns:
            List of log entries (newest last)
        """
        key = f"logs:{job_id}"
        logs = self.r.lrange(key, -limit, -1)
        
        return [json.loads(log) for log in logs]
    
    def get_recent_logs(self, limit: int = 100) -> list[Dict]:
        """Get recent logs from all jobs."""
        logs = self.r.lrange("logs:all", -limit, -1)
        return [json.loads(log) for log in logs]
    
    def clear_job_logs(self, job_id: str):
        """Clear all logs for a job."""
        key = f"logs:{job_id}"
        self.r.delete(key)


# Singleton instances per component
_loggers: Dict[str, SystemLogger] = {}

def get_logger(component: str = "sentinel") -> SystemLogger:
    """
    Get logger instance for a component.
    
    Args:
        component: Component name (worker, api, scanner, etc.)
        
    Returns:
        SystemLogger instance
    """
    if component not in _loggers:
        _loggers[component] = SystemLogger(component=component)
    return _loggers[component]

