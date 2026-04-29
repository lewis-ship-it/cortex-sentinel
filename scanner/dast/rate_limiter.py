# scanner/dast/rate_limiter.py
#
# ENHANCED RATE LIMITER — Comprehensive rate limiting with multiple algorithms,
# adaptive controls, and advanced features for security scanning

import time
import asyncio
import threading
from typing import Dict, Optional, Set, List, Tuple, Union
from urllib.parse import urlparse
from collections import defaultdict, deque
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class RateLimitAlgorithm(Enum):
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"

@dataclass
class RateLimitConfig:
    requests_per_second: float = 2.0
    burst_size: int = 5
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.TOKEN_BUCKET
    max_domains: int = 1000
    cleanup_interval: float = 300.0  # 5 minutes
    adaptive: bool = False
    max_retry_after: float = 30.0  # Maximum wait time

class RateLimiter:
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        
        # Token bucket state
        self.tokens: Dict[str, float] = {}
        self.last_request: Dict[str, float] = {}
        
        # Leaky bucket state
        self.queues: Dict[str, deque] = {}
        
        # Fixed window state
        self.window_counts: Dict[str, int] = {}
        self.window_start: Dict[str, float] = {}
        
        # Sliding window state
        self.request_logs: Dict[str, deque] = {}
        
        # Adaptive rate limiting
        self.domain_penalties: Dict[str, float] = {}
        self.success_rates: Dict[str, float] = {}
        
        # Statistics
        self.stats = {
            "total_requests": 0,
            "rate_limited": 0,
            "domains_seen": set(),
            "max_wait_time": 0.0
        }
        
        # Cleanup thread
        self._cleanup_lock = threading.Lock()
        self._cleanup_thread = None
        self._running = True
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        """Start background cleanup thread."""
        def cleanup_loop():
            while self._running:
                time.sleep(self.config.cleanup_interval)
                self._cleanup_old_entries()
        
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def _cleanup_old_entries(self):
        """Clean up old rate limiting entries."""
        with self._cleanup_lock:
            current_time = time.time()
            cleanup_age = current_time - 3600  # 1 hour
            
            # Cleanup token bucket
            old_domains = [
                domain for domain, last_req in self.last_request.items()
                if last_req < cleanup_age
            ]
            for domain in old_domains:
                self.tokens.pop(domain, None)
                self.last_request.pop(domain, None)
                self.queues.pop(domain, None)
                self.window_counts.pop(domain, None)
                self.window_start.pop(domain, None)
                self.request_logs.pop(domain, None)
                self.domain_penalties.pop(domain, None)
                self.success_rates.pop(domain, None)
            
            # Limit number of domains
            if len(self.last_request) > self.config.max_domains:
                # Remove oldest domains
                domains_by_age = sorted(
                    self.last_request.keys(),
                    key=lambda d: self.last_request[d]
                )
                domains_to_remove = domains_by_age[:len(self.last_request) - self.config.max_domains]
                for domain in domains_to_remove:
                    self.tokens.pop(domain, None)
                    self.last_request.pop(domain, None)
                    self.queues.pop(domain, None)
                    self.window_counts.pop(domain, None)
                    self.window_start.pop(domain, None)
                    self.request_logs.pop(domain, None)
                    self.domain_penalties.pop(domain, None)
                    self.success_rates.pop(domain, None)

    def _get_domain_key(self, identifier: str) -> str:
        """Extract domain from identifier."""
        if "://" in identifier:
            try:
                return urlparse(identifier).netloc
            except ValueError:
                return identifier
        return identifier

    def _calculate_adaptive_rate(self, domain: str, success: bool) -> float:
        """Calculate adaptive rate limit based on success rate."""
        if not self.config.adaptive:
            return self.config.requests_per_second
        
        # Update success rate (moving average)
        current_rate = self.success_rates.get(domain, 1.0)
        new_rate = 0.9 * current_rate + 0.1 * (1.0 if success else 0.0)
        self.success_rates[domain] = new_rate
        
        # Adjust rate based on success
        if new_rate < 0.3:  # Low success rate
            penalty = max(0.1, new_rate)  # Reduce rate significantly
            return self.config.requests_per_second * penalty
        elif new_rate > 0.9:  # High success rate
            boost = min(2.0, 1.0 + (new_rate - 0.9) * 10)  # Increase rate
            return self.config.requests_per_second * boost
        else:
            return self.config.requests_per_second

    def _token_bucket_allow(self, domain: str) -> Tuple[bool, float]:
        """Token bucket rate limiting algorithm."""
        current_time = time.time()
        last_time = self.last_request.get(domain, current_time)
        
        # Calculate tokens to add
        elapsed = current_time - last_time
        tokens_to_add = elapsed * self.config.requests_per_second
        
        # Update tokens
        current_tokens = self.tokens.get(domain, self.config.burst_size)
        new_tokens = min(current_tokens + tokens_to_add, self.config.burst_size)
        
        # Check if request is allowed
        if new_tokens >= 1.0:
            self.tokens[domain] = new_tokens - 1.0
            self.last_request[domain] = current_time
            return True, 0.0
        else:
            # Calculate wait time
            wait_time = (1.0 - new_tokens) / self.config.requests_per_second
            return False, wait_time

    def _leaky_bucket_allow(self, domain: str) -> Tuple[bool, float]:
        """Leaky bucket rate limiting algorithm."""
        current_time = time.time()
        queue = self.queues.setdefault(domain, deque())
        
        # Remove old requests
        while queue and queue[0] <= current_time - 1.0:
            queue.popleft()
        
        # Check if bucket is full
        if len(queue) < self.config.burst_size:
            queue.append(current_time)
            self.last_request[domain] = current_time
            return True, 0.0
        else:
            # Calculate wait time until next slot
            oldest_request = queue[0]
            wait_time = max(0.0, (oldest_request + 1.0) - current_time)
            return False, wait_time

    def _fixed_window_allow(self, domain: str) -> Tuple[bool, float]:
        """Fixed window rate limiting algorithm."""
        current_time = time.time()
        window_start = self.window_start.get(domain, current_time)
        
        # Check if window has expired
        if current_time - window_start >= 1.0:
            self.window_counts[domain] = 0
            self.window_start[domain] = current_time
        
        # Get current count
        count = self.window_counts.get(domain, 0)
        
        # Check if request is allowed
        if count < self.config.burst_size:
            self.window_counts[domain] = count + 1
            self.last_request[domain] = current_time
            return True, 0.0
        else:
            # Calculate wait time until next window
            wait_time = max(0.0, (window_start + 1.0) - current_time)
            return False, wait_time

    def _sliding_window_allow(self, domain: str) -> Tuple[bool, float]:
        """Sliding window rate limiting algorithm."""
        current_time = time.time()
        requests = self.request_logs.setdefault(domain, deque())
        
        # Remove requests outside current window
        while requests and requests[0] <= current_time - 1.0:
            requests.popleft()
        
        # Check if request is allowed
        if len(requests) < self.config.burst_size:
            requests.append(current_time)
            self.last_request[domain] = current_time
            return True, 0.0
        else:
            # Calculate wait time until next slot
            oldest_request = requests[0]
            wait_time = max(0.0, (oldest_request + 1.0) - current_time)
            return False, wait_time

    def allow(self, identifier: str, delay: Optional[float] = None) -> Tuple[bool, float]:
        """
        Check if a request is allowed and return wait time if not.
        
        Args:
            identifier: Domain or URL to rate limit
            delay: Optional custom delay override
            
        Returns:
            Tuple of (allowed, wait_time_seconds)
        """
        domain = self._get_domain_key(identifier)
        current_time = time.time()
        
        # Apply adaptive rate limiting
        effective_rate = self._calculate_adaptive_rate(domain, True)
        if effective_rate != self.config.requests_per_second:
            # Create temporary config for adaptive rate
            adaptive_config = RateLimitConfig(
                requests_per_second=effective_rate,
                burst_size=self.config.burst_size,
                algorithm=self.config.algorithm
            )
            original_config = self.config
            self.config = adaptive_config
            try:
                return self._allow_with_algorithm(domain)
            finally:
                self.config = original_config
        else:
            return self._allow_with_algorithm(domain)

    def _allow_with_algorithm(self, domain: str) -> Tuple[bool, float]:
        """Apply the configured rate limiting algorithm."""
        if self.config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            return self._token_bucket_allow(domain)
        elif self.config.algorithm == RateLimitAlgorithm.LEAKY_BUCKET:
            return self._leaky_bucket_allow(domain)
        elif self.config.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
            return self._fixed_window_allow(domain)
        elif self.config.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
            return self._sliding_window_allow(domain)
        else:
            # Default to token bucket
            return self._token_bucket_allow(domain)

    async def allow_async(self, identifier: str) -> Tuple[bool, float]:
        """Async version of allow."""
        return self.allow(identifier)

    def wait(self, identifier: str) -> None:
        """
        Wait until a request is allowed.
        
        Args:
            identifier: Domain or URL to wait for
        """
        domain = self._get_domain_key(identifier)
        
        while True:
            allowed, wait_time = self.allow(domain)
            if allowed:
                break
            else:
                # Cap wait time to avoid long blocks
                wait_time = min(wait_time, self.config.max_retry_after)
                time.sleep(wait_time)
                
                # Update statistics
                self.stats["max_wait_time"] = max(self.stats["max_wait_time"], wait_time)

    async def wait_async(self, identifier: str) -> None:
        """Async version of wait."""
        domain = self._get_domain_key(identifier)
        
        while True:
            allowed, wait_time = await self.allow_async(domain)
            if allowed:
                break
            else:
                wait_time = min(wait_time, self.config.max_retry_after)
                await asyncio.sleep(wait_time)
                self.stats["max_wait_time"] = max(self.stats["max_wait_time"], wait_time)

    def update_success(self, identifier: str, success: bool) -> None:
        """
        Update success rate for adaptive rate limiting.
        
        Args:
            identifier: Domain or URL
            success: Whether the request was successful
        """
        if self.config.adaptive:
            domain = self._get_domain_key(identifier)
            self._calculate_adaptive_rate(domain, success)

    def get_stats(self) -> Dict:
        """Get rate limiting statistics."""
        return {
            **self.stats,
            "active_domains": len(self.last_request),
            "current_time": time.time(),
            "config": {
                "requests_per_second": self.config.requests_per_second,
                "burst_size": self.config.burst_size,
                "algorithm": self.config.algorithm.value,
                "adaptive": self.config.adaptive
            }
        }

    def set_rate(self, requests_per_second: float, burst_size: Optional[int] = None) -> None:
        """
        Dynamically update rate limiting configuration.
        
        Args:
            requests_per_second: New requests per second rate
            burst_size: New burst size (optional)
        """
        self.config.requests_per_second = requests_per_second
        if burst_size is not None:
            self.config.burst_size = burst_size

    def penalize_domain(self, identifier: str, penalty_factor: float = 0.5) -> None:
        """
        Apply temporary penalty to a domain's rate limit.
        
        Args:
            identifier: Domain or URL to penalize
            penalty_factor: Multiplier for rate reduction (0.0-1.0)
        """
        domain = self._get_domain_key(identifier)
        self.domain_penalties[domain] = penalty_factor

    def remove_penalty(self, identifier: str) -> None:
        """Remove penalty from a domain."""
        domain = self._get_domain_key(identifier)
        self.domain_penalties.pop(domain, None)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    def shutdown(self):
        """Clean shutdown of rate limiter."""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=1.0)

# Legacy compatibility class
class SimpleRateLimiter:
    """Legacy rate limiter for backward compatibility."""
    
    def __init__(self):
        self._limiter = RateLimiter()
    
    def allow(self, identifier, delay: float = 0.5) -> bool:
        allowed, _ = self._limiter.allow(identifier)
        return allowed
    
    def wait(self, identifier, delay: float = 0.5) -> None:
        self._limiter.wait(identifier)

# Global instance for simple usage
_global_rate_limiter = RateLimiter()

def allow(identifier: str) -> bool:
    """Global allow function for backward compatibility."""
    allowed, _ = _global_rate_limiter.allow(identifier)
    return allowed

def wait(identifier: str) -> None:
    """Global wait function for backward compatibility."""
    _global_rate_limiter.wait(identifier)
