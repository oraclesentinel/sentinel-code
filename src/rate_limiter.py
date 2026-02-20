"""
Rate Limiter for Sentinel Code
Implements IP-based rate limiting for free tier
"""

import time
import threading
from collections import defaultdict
from typing import Dict, Tuple

class RateLimiter:
    """
    Simple IP-based rate limiter with daily reset.
    
    Free tier: 3 scans per day per IP
    """
    
    def __init__(self, max_requests: int = 3, window_seconds: int = 86400):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests per window (default: 3)
            window_seconds: Time window in seconds (default: 86400 = 24 hours)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list] = defaultdict(list)
        self.lock = threading.Lock()
    
    def _cleanup_old_requests(self, ip: str, now: float) -> None:
        """Remove requests outside the current window."""
        cutoff = now - self.window_seconds
        self.requests[ip] = [ts for ts in self.requests[ip] if ts > cutoff]
    
    def is_allowed(self, ip: str) -> Tuple[bool, int, int]:
        """
        Check if request from IP is allowed.
        
        Args:
            ip: Client IP address
            
        Returns:
            Tuple of (allowed, remaining, reset_in_seconds)
        """
        with self.lock:
            now = time.time()
            self._cleanup_old_requests(ip, now)
            
            current_count = len(self.requests[ip])
            remaining = max(0, self.max_requests - current_count)
            
            # Calculate reset time
            if self.requests[ip]:
                oldest = min(self.requests[ip])
                reset_in = int(oldest + self.window_seconds - now)
            else:
                reset_in = self.window_seconds
            
            if current_count >= self.max_requests:
                return False, 0, reset_in
            
            return True, remaining, reset_in
    
    def record_request(self, ip: str) -> None:
        """Record a request from IP."""
        with self.lock:
            now = time.time()
            self._cleanup_old_requests(ip, now)
            self.requests[ip].append(now)
    
    def get_usage(self, ip: str) -> dict:
        """Get usage stats for IP."""
        with self.lock:
            now = time.time()
            self._cleanup_old_requests(ip, now)
            
            current_count = len(self.requests[ip])
            remaining = max(0, self.max_requests - current_count)
            
            if self.requests[ip]:
                oldest = min(self.requests[ip])
                reset_in = int(oldest + self.window_seconds - now)
            else:
                reset_in = self.window_seconds
            
            return {
                "used": current_count,
                "remaining": remaining,
                "limit": self.max_requests,
                "reset_in_seconds": reset_in,
                "window_hours": self.window_seconds // 3600
            }
    
    def reset(self, ip: str = None) -> None:
        """Reset rate limit for IP or all IPs."""
        with self.lock:
            if ip:
                self.requests[ip] = []
            else:
                self.requests.clear()


# Global rate limiter instance
# 3 scans per 24 hours
rate_limiter = RateLimiter(max_requests=3, window_seconds=86400)


def get_client_ip(request) -> str:
    """
    Get client IP from request, handling proxies.
    
    Args:
        request: Flask request object
        
    Returns:
        Client IP address
    """
    # Check for proxy headers
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs, take the first
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or '127.0.0.1'
