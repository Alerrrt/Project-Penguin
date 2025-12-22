from typing import Dict, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, max_requests: int, time_window: int):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed in the time window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: Dict[str, list] = defaultdict(list)
        self.blocked_clients: Dict[str, datetime] = {}

    def check_rate_limit(self, client_id: str) -> bool:
        """
        Soft rate limit for realtime updates: return False when above window; do not hard-block client.
        """
        now = datetime.now()
        # Remove old requests
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if now - req_time < timedelta(seconds=self.time_window)
        ]
        # Soft drop if exceeded
        if len(self.requests[client_id]) >= self.max_requests:
            # Trace occasionally at debug level
            if len(self.requests[client_id]) % max(1, self.max_requests // 5) == 0:
                logger.debug("Soft drop due to WS rate limit for client %s", client_id)
            return False
        # Record request
        self.requests[client_id].append(now)
        return True

    def get_retry_after(self, client_id: str) -> Optional[int]:
        """
        Get the number of seconds until a client can make another request.
        
        Args:
            client_id: Unique identifier for the client
            
        Returns:
            Optional[int]: Number of seconds until retry is allowed, or None if not blocked
        """
        if client_id in self.blocked_clients:
            retry_after = (self.blocked_clients[client_id] - datetime.now()).total_seconds()
            return max(0, int(retry_after))
        return None

    def reset(self, client_id: str):
        """
        Reset rate limit for a client.
        
        Args:
            client_id: Unique identifier for the client
        """
        if client_id in self.requests:
            del self.requests[client_id]
        if client_id in self.blocked_clients:
            del self.blocked_clients[client_id]

    def get_client_stats(self, client_id: str) -> dict:
        """
        Get rate limit statistics for a client.
        
        Args:
            client_id: Unique identifier for the client
            
        Returns:
            dict: Statistics including request count and time until reset
        """
        now = datetime.now()
        requests = self.requests.get(client_id, [])
        
        # Remove old requests
        valid_requests = [
            req_time for req_time in requests
            if now - req_time < timedelta(seconds=self.time_window)
        ]
        
        return {
            "request_count": len(valid_requests),
            "max_requests": self.max_requests,
            "time_window": self.time_window,
            "is_blocked": False,
            "retry_after": None,
            "requests_remaining": max(0, self.max_requests - len(valid_requests))
        } 
