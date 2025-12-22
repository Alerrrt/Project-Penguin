import asyncio
import hashlib
import json
import time
import random
from typing import AsyncIterator, Optional, Dict, Any, Tuple, List
from contextlib import asynccontextmanager
import httpx
from collections import OrderedDict
import logging
from urllib.parse import urlparse
import ipaddress
import socket

try:
    # Optional settings integration
    from backend.config import settings as _app_settings
    _DEFAULT_BLOCK_PRIVATE = bool(getattr(_app_settings, 'BLOCK_PRIVATE_NETWORKS', False))
    _DEFAULT_HTTP_MAX_RETRIES = int(getattr(_app_settings, 'HTTP_MAX_RETRIES', 3))  # Increased from 2 to 3
    _DEFAULT_HTTP_BACKOFF_BASE = float(getattr(_app_settings, 'HTTP_BACKOFF_BASE_SECONDS', 0.1))  # Reduced from 0.2 to 0.1
    _DEFAULT_HTTP_BACKOFF_MAX = float(getattr(_app_settings, 'HTTP_BACKOFF_MAX_SECONDS', 2.0))  # Reduced from 5.0 to 2.0
    _DEFAULT_HTTP_PER_HOST_INTERVAL_MS = int(getattr(_app_settings, 'HTTP_PER_HOST_MIN_INTERVAL_MS', 0))  # Reduced from 2 to 0
    _DEFAULT_ALLOWED_HOSTS = list(getattr(_app_settings, 'HTTP_ALLOWED_HOSTS', []) or [])
    _DEFAULT_BLOCKED_HOSTS = list(getattr(_app_settings, 'HTTP_BLOCKED_HOSTS', []) or [])
    _DEFAULT_MAX_RESPONSE_BYTES = int(getattr(_app_settings, 'HTTP_MAX_RESPONSE_BYTES', 0))
    _DEFAULT_ACCEPT_LANGUAGE = str(getattr(_app_settings, 'HTTP_ACCEPT_LANGUAGE', 'en-US,en;q=0.9'))
    _DEFAULT_BUCKET_MAX_TOKENS = int(getattr(_app_settings, 'HTTP_BUCKET_MAX_TOKENS', 100))  # Increased from 40 to 100
    _DEFAULT_BUCKET_REFILL_PER_SEC = float(getattr(_app_settings, 'HTTP_BUCKET_REFILL_PER_SEC', 50.0))  # Increased from 20.0 to 50.0
except Exception:
    _DEFAULT_BLOCK_PRIVATE = False
    _DEFAULT_HTTP_MAX_RETRIES = 3
    _DEFAULT_HTTP_BACKOFF_BASE = 0.05  # Reduced to 0.05 for faster retries
    _DEFAULT_HTTP_BACKOFF_MAX = 1.0  # Reduced to 1.0 for faster retries
    _DEFAULT_HTTP_PER_HOST_INTERVAL_MS = 0  # No delay between requests
    _DEFAULT_ALLOWED_HOSTS = []
    _DEFAULT_BLOCKED_HOSTS = []
    _DEFAULT_MAX_RESPONSE_BYTES = 0
    _DEFAULT_ACCEPT_LANGUAGE = 'en-US,en;q=0.9'
    _DEFAULT_BUCKET_MAX_TOKENS = 200  # Increased to 200 for more concurrent requests
    _DEFAULT_BUCKET_REFILL_PER_SEC = 100.0  # Increased to 100.0 for faster token refill

logger = logging.getLogger(__name__)

class HTTPResponseCache:
    """Simple in-memory cache for HTTP responses with TTL."""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self._lock = asyncio.Lock()
    
    def _make_key(self, method: str, url: str, headers: Dict, body: Optional[str] = None) -> str:
        """Create a cache key from request parameters."""
        key_data = {
            'method': method.upper(),
            'url': url,
            'headers': sorted(headers.items()),
            'body': body or ''
        }
        return hashlib.md5(json.dumps(key_data, sort_keys=True).encode()).hexdigest()
    
    async def get(self, method: str, url: str, headers: Dict, body: Optional[str] = None) -> Optional[Any]:
        """Get cached response if available and not expired."""
        async with self._lock:
            key = self._make_key(method, url, headers, body)
            if key in self.cache:
                response, timestamp = self.cache[key]
                if time.time() - timestamp < self.default_ttl:
                    # Move to end (LRU)
                    self.cache.move_to_end(key)
                    logger.debug(f"Cache hit for {method} {url}")
                    return response
                else:
                    # Expired, remove
                    del self.cache[key]
            return None
    
    async def set(self, method: str, url: str, headers: Dict, body: Optional[str] = None, 
                  response: Any = None, ttl: Optional[int] = None) -> None:
        """Cache a response with optional custom TTL."""
        async with self._lock:
            key = self._make_key(method, url, headers, body)
            ttl = ttl or self.default_ttl
            
            # Remove oldest if at capacity
            if len(self.cache) >= self.max_size:
                self.cache.popitem(last=False)
            
            self.cache[key] = (response, time.time())
            logger.debug(f"Cached response for {method} {url}")

class SharedHTTPClient:
    """Shared HTTP client with connection pooling, caching, and request deduplication."""
    
    def __init__(self, 
                  max_connections: int = 1000,  # Increased from 600 to 1000 for more concurrent connections
                  max_keepalive_connections: int = 400,  # Increased from 200 to 400 for better connection reuse
                 keepalive_expiry: float = 120.0,  # Increased from 60.0 to 120.0 for longer connection reuse
                 cache_max_size: int = 5000,  # Increased from 2000 to 5000 for better cache hit rate
                 cache_default_ttl: int = 300,
                 # Retry configuration
                 default_max_retries: int = _DEFAULT_HTTP_MAX_RETRIES,
                 backoff_base_seconds: float = _DEFAULT_HTTP_BACKOFF_BASE,
                 backoff_max_seconds: float = _DEFAULT_HTTP_BACKOFF_MAX,
                 retry_status_codes: Optional[List[int]] = None,
                 # Simple per-host throttling to avoid hammering a single origin
                  per_host_min_interval_ms: int = _DEFAULT_HTTP_PER_HOST_INTERVAL_MS,
                 allowed_hosts: Optional[List[str]] = None,
                 blocked_hosts: Optional[List[str]] = None,
                 max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
                  accept_language: str = _DEFAULT_ACCEPT_LANGUAGE,
                  bucket_max_tokens: int = _DEFAULT_BUCKET_MAX_TOKENS,
                  bucket_refill_per_sec: float = _DEFAULT_BUCKET_REFILL_PER_SEC):
        
        self.max_connections = max_connections
        self.max_keepalive_connections = max_keepalive_connections
        self.keepalive_expiry = keepalive_expiry
        self.cache = HTTPResponseCache(cache_max_size, cache_default_ttl)
        self._active_requests: Dict[str, asyncio.Task] = {}
        self._request_lock = asyncio.Lock()
        self._host_lock = asyncio.Lock()
        self._host_next_available: Dict[str, float] = {}
        self._metrics: Dict[str, int] = {
            "retries": 0,
            "throttle_waits": 0,
            "ssrf_blocks": 0,
        }
        
        # Retry policy
        self.default_max_retries = default_max_retries
        self.backoff_base_seconds = backoff_base_seconds
        self.backoff_max_seconds = backoff_max_seconds
        self.retry_status_codes = retry_status_codes or [429, 500, 502, 503, 504]
        
        # Throttling
        self.per_host_min_interval = max(0.0, per_host_min_interval_ms / 1000.0)
        
        # Policy
        self.allowed_hosts = set((allowed_hosts if allowed_hosts is not None else _DEFAULT_ALLOWED_HOSTS))
        self.blocked_hosts = set((blocked_hosts if blocked_hosts is not None else _DEFAULT_BLOCKED_HOSTS))
        self.max_response_bytes = max(0, int(max_response_bytes))
        self.accept_language = accept_language

        # Per-host token buckets (optional)
        self._bucket_max_tokens = max(0, int(bucket_max_tokens))
        self._bucket_refill_per_sec = max(0.0, float(bucket_refill_per_sec))
        self._host_buckets: Dict[str, Tuple[float, float]] = {}  # host -> (tokens, last_refill_time)

        # Connection pool limits
        self._limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry
        )
    
    def _get_client_config(self, 
                          timeout: float = 30.0,
                          verify: bool = False,
                          follow_redirects: bool = True,
                          headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get client configuration with defaults."""
        default_headers = {
            # Use a modern browser UA to avoid naive bot blocks (many sites 403 on custom agents)
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36 Project-Echo/2.0"
            ),
            "Accept-Language": self.accept_language,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/\*;q=0.8",
            "Connection": "keep-alive",
        }
        
        merged_headers = {**default_headers, **(headers or {})}
        
        return {
            "timeout": timeout,
            "verify": verify,
            "follow_redirects": follow_redirects,
            "headers": merged_headers,
            "limits": self._limits
        }
    
    def _make_request_id(self, method: str, url: str, headers: Dict,
                         body: Optional[str] = None,
                         params: Optional[Dict[str, Any]] = None,
                         json_payload: Optional[Any] = None,
                         data: Optional[Any] = None) -> str:
        try:
            params_part = hash(frozenset((params or {}).items()))
        except Exception:
            params_part = hash(str(params))
        try:
            json_part = hash(json.dumps(json_payload, sort_keys=True)) if json_payload is not None else 0
        except Exception:
            json_part = hash(str(json_payload))
        data_part = hash(str(data)) if data is not None else 0
        return f"{method}:{url}:{hash(frozenset(headers.items()))}:{hash(body)}:{params_part}:{json_part}:{data_part}"

    async def _deduplicate_request(self, method: str, url: str, headers: Dict, 
                                  body: Optional[str] = None,
                                  params: Optional[Dict[str, Any]] = None,
                                  json_payload: Optional[Any] = None,
                                  data: Optional[Any] = None) -> Optional[Any]:
        """Check if identical request is already in progress and wait for result."""
        # Fast path: only deduplicate GET/HEAD requests for better performance
        if method.upper() not in ['GET', 'HEAD']:
            return None
            
        request_id = self._make_request_id(method, url, headers, body, params, json_payload, data)
        
        async with self._request_lock:
            if request_id in self._active_requests:
                # Wait for existing request to complete
                existing_task = self._active_requests[request_id]
                logger.debug(f"Deduplicating request {method} {url}")
                try:
                    return await existing_task
                except Exception as e:
                    logger.warning(f"Deduplicated request failed: {e}")
                    return None
            return None
    
    async def _mark_request_complete(self, method: str, url: str, headers: Dict, 
                                    body: Optional[str] = None,
                                    params: Optional[Dict[str, Any]] = None,
                                    json_payload: Optional[Any] = None,
                                    data: Optional[Any] = None) -> None:
        """Mark request as complete and remove from active requests."""
        request_id = self._make_request_id(method, url, headers, body, params, json_payload, data)
        async with self._request_lock:
            if request_id in self._active_requests:
                del self._active_requests[request_id]
    
    async def request(self, 
                     method: str,
                     url: str,
                     headers: Optional[Dict[str, str]] = None,
                     body: Optional[str] = None,
                     params: Optional[Dict[str, Any]] = None,
                     json: Optional[Any] = None,
                     data: Optional[Any] = None,
                     cookies: Optional[Dict[str, Any]] = None,
                     timeout: float = 30.0,
                     verify: bool = False,
                     follow_redirects: bool = True,
                     use_cache: bool = True,
                     cache_ttl: Optional[int] = None,
                     # Override retry policy per call if desired
                     max_retries: Optional[int] = None,
                     backoff_base_seconds: Optional[float] = None,
                     backoff_max_seconds: Optional[float] = None,
                     retry_status_codes: Optional[List[int]] = None,
                     # SSRF guard options
                     block_private_networks: Optional[bool] = None) -> httpx.Response:
        """Make an HTTP request with caching and deduplication."""
        # Host allow/deny
        parsed = urlparse(url)
        host = parsed.hostname or ''
        if self.allowed_hosts and host not in self.allowed_hosts:
            logger.warning("HTTP blocked by allowlist", extra={"url": url, "host": host, "component": "http_client"})
            raise RuntimeError("Blocked by allowlist policy")
        if self.blocked_hosts and host in self.blocked_hosts:
            logger.warning("HTTP blocked by blocklist", extra={"url": url, "host": host, "component": "http_client"})
            raise RuntimeError("Blocked by blocklist policy")

        # SSRF safeguard (configurable)
        allow_public_only = _DEFAULT_BLOCK_PRIVATE if block_private_networks is None else bool(block_private_networks)
        if allow_public_only and not self._is_public_url(url):
            try:
                self._metrics["ssrf_blocks"] += 1
            except Exception:
                pass
            logger.warning(
                "HTTP request blocked by SSRF safeguard",
                extra={"url": url, "component": "http_client", "reason": "private_network"}
            )
            raise RuntimeError("Blocked by SSRF safeguard: private or disallowed network destination")
        
        # Check cache first
        if use_cache and method.upper() in ['GET', 'HEAD']:
            cached_response = await self.cache.get(method, url, headers or {}, body)
            if cached_response:
                return cached_response
        
        # Check for duplicate requests
        dedup_result = await self._deduplicate_request(method, url, headers or {}, body, params, json, data)
        if dedup_result:
            return dedup_result
        
        # Create new request task
        async def _make_request():
            try:
                config = self._get_client_config(timeout, verify, follow_redirects, headers)
                chosen_max_retries = self.default_max_retries if max_retries is None else max(0, int(max_retries))
                chosen_backoff_base = self.backoff_base_seconds if backoff_base_seconds is None else max(0.0, float(backoff_base_seconds))
                chosen_backoff_max = self.backoff_max_seconds if backoff_max_seconds is None else max(0.0, float(backoff_max_seconds))
                chosen_retry_statuses = self.retry_status_codes if retry_status_codes is None else list(retry_status_codes)

                last_exc: Optional[Exception] = None
                attempt = 0
                async with httpx.AsyncClient(**config) as client:
                    while attempt <= chosen_max_retries:
                        # Per-host throttle and optional token bucket pacing
                        try:
                            await self._throttle_host(url)
                            await self._pacer_host(url)
                        except Exception:
                            # Throttling should never break the request; continue anyway
                            pass

                        try:
                            response = await client.request(
                                method,
                                url,
                                headers=config['headers'],
                                content=body,
                                params=params,
                                json=json,
                                data=data,
                                cookies=cookies,
                            )
                            # Optionally cap response size for safety (streaming not used here; lightweight check)
                            if self.max_response_bytes and len(response.content or b"") > self.max_response_bytes:
                                logger.warning(
                                    "HTTP response truncated by size limit",
                                    extra={"url": url, "limit_bytes": self.max_response_bytes, "component": "http_client"}
                                )
                                # Create a shallow clone with truncated content
                                truncated = httpx.Response(
                                    status_code=response.status_code,
                                    headers=response.headers,
                                    request=response.request,
                                    content=(response.content or b"")[: self.max_response_bytes],
                                )
                                response = truncated
                            # Retry on certain response codes
                            if response.status_code in chosen_retry_statuses:
                                if attempt >= chosen_max_retries:
                                    break
                                # Honor Retry-After when available
                                retry_after = 0.0
                                try:
                                    ra = response.headers.get('Retry-After')
                                    if ra:
                                        if ra.isdigit():
                                            retry_after = float(ra)
                                        else:
                                            # HTTP-date not parsed; ignore for simplicity
                                            pass
                                except Exception:
                                    pass
                                await self._sleep_with_backoff(attempt, chosen_backoff_base, chosen_backoff_max, retry_after)
                                try:
                                    self._metrics["retries"] += 1
                                except Exception:
                                    pass
                                logger.info(
                                    "HTTP retry due to status",
                                    extra={
                                        "url": url,
                                        "status": response.status_code,
                                        "attempt": attempt + 1,
                                        "component": "http_client"
                                    }
                                )
                                attempt += 1
                                continue
                            # Success path
                            if use_cache and method.upper() in ['GET', 'HEAD'] and response.status_code < 400:
                                await self.cache.set(method, url, headers or {}, body, response, cache_ttl)
                            return response
                        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError) as e:
                            last_exc = e
                            if attempt >= chosen_max_retries:
                                raise
                            await self._sleep_with_backoff(attempt, chosen_backoff_base, chosen_backoff_max)
                            try:
                                self._metrics["retries"] += 1
                            except Exception:
                                pass
                            logger.info(
                                "HTTP retry due to network error",
                                extra={
                                    "url": url,
                                    "error": type(e).__name__,
                                    "attempt": attempt + 1,
                                    "component": "http_client"
                                }
                            )
                            attempt += 1
                        except Exception as e:
                            # Non-network exception: don't retry by default
                            last_exc = e
                            raise
                    # End of while
                    # No early return; either out of retries or last response to be returned
                    if 'response' in locals():
                        return response
                    if last_exc:
                        raise last_exc
                    # Fallback
                    raise RuntimeError("HTTP request failed without response and without exception")
            finally:
                await self._mark_request_complete(method, url, headers or {}, body, params, json, data)
        
        # Create and track the task
        task = asyncio.create_task(_make_request())
        request_id = self._make_request_id(method, url, headers or {}, body, params, json, data)
        
        async with self._request_lock:
            self._active_requests[request_id] = task
        
        return await task

    def _is_public_url(self, url: str) -> bool:
        """Return True if the URL resolves to a public IP and uses http/https."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False
            host = parsed.hostname
            if not host:
                return False
            # If host is already an IP, check directly
            try:
                ip_obj = ipaddress.ip_address(host)
                return self._is_public_ip(ip_obj)
            except ValueError:
                pass
            # Resolve hostname to IPs; if any private, treat as private
            try:
                infos = socket.getaddrinfo(host, None)
                for info in infos:
                    addr = info[4][0]
                    try:
                        ip_obj = ipaddress.ip_address(addr)
                        if not self._is_public_ip(ip_obj):
                            return False
                    except ValueError:
                        return False
                return True if infos else False
            except Exception:
                # If we cannot resolve, be conservative and block
                return False
        except Exception:
            return False

    @staticmethod
    def _is_public_ip(ip_obj: ipaddress._BaseAddress) -> bool:
        """True if IP is not private, loopback, link-local, multicast, or reserved."""
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        )

    async def _sleep_with_backoff(self, attempt: int, base: float, max_backoff: float, floor_seconds: float = 0.0) -> None:
        """Sleep using exponential backoff with jitter and optional floor (Retry-After)."""
        exp = base * (2 ** attempt)
        delay = min(max_backoff, exp)
        # Full jitter
        jitter = random.uniform(0, delay)
        sleep_for = max(floor_seconds, jitter)
        await asyncio.sleep(sleep_for)

    async def _throttle_host(self, url: str) -> None:
        """Apply a simple per-host minimum interval between requests to avoid hammering a single origin."""
        if self.per_host_min_interval <= 0:
            return
        try:
            host = urlparse(url).netloc
        except Exception:
            host = ''
        if not host:
            return
        now = time.time()
        async with self._host_lock:
            next_allowed = self._host_next_available.get(host, 0.0)
            if now < next_allowed:
                wait_for = next_allowed - now
                # Skip very small waits for performance
                if wait_for < 0.005:  # Skip waits under 5ms
                    return
                try:
                    self._metrics["throttle_waits"] += 1
                except Exception:
                    pass
                logger.debug(
                    "Per-host throttle wait",
                    extra={"host": host, "wait_seconds": round(wait_for, 4), "component": "http_client"}
                )
                await asyncio.sleep(wait_for)
                now = time.time()
            # Set next available time
            self._host_next_available[host] = now + self.per_host_min_interval

    async def _pacer_host(self, url: str) -> None:
        """Token-bucket per-host pacing; optional and disabled when max_tokens <= 0."""
        if self._bucket_max_tokens <= 0 or self._bucket_refill_per_sec <= 0:
            return
        try:
            host = urlparse(url).netloc
        except Exception:
            host = ''
        if not host:
            return
            
        # Check if this is a critical scanner host that should get priority
        is_critical_host = any(critical in host for critical in [
            'security', 'auth', 'login', 'api', 'admin', 'dashboard'
        ])
            
        now = time.time()
        async with self._host_lock:
            tokens, last_refill = self._host_buckets.get(host, (float(self._bucket_max_tokens), now))
            # Refill
            elapsed = max(0.0, now - last_refill)
            tokens = min(float(self._bucket_max_tokens), tokens + elapsed * self._bucket_refill_per_sec)
            
            # For critical hosts, ensure we always have at least 2 tokens available
            if is_critical_host and tokens < 2.0:
                tokens = 2.0
                
            if tokens < 1.0:
                # Need to wait until at least 1 token is available
                needed = 1.0 - tokens
                # Reduce wait time by 50% for faster scanning
                wait_for = (needed / self._bucket_refill_per_sec) * 0.5
                try:
                    self._metrics["throttle_waits"] += 1
                except Exception:
                    pass
                await asyncio.sleep(wait_for)
                now = time.time()
                # Refill after sleep
                elapsed = max(0.0, now - (last_refill + elapsed))
                tokens = min(float(self._bucket_max_tokens), tokens + elapsed * self._bucket_refill_per_sec)
            
            # Consume tokens (less for critical hosts)
            token_cost = 0.5 if is_critical_host else 1.0
            tokens = max(0.0, tokens - token_cost)
            self._host_buckets[host] = (tokens, now)
    
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Convenience method for GET requests."""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Convenience method for POST requests."""
        return await self.request('POST', url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> httpx.Response:
        """Convenience method for HEAD requests."""
        return await self.request('HEAD', url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> httpx.Response:
        """Convenience method for OPTIONS requests."""
        return await self.request('OPTIONS', url, **kwargs)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics for monitoring."""
        return {
            "cache_size": len(self.cache.cache),
            "active_requests": len(self._active_requests),
            "max_connections": self.max_connections,
            "max_keepalive": self.max_keepalive_connections,
            "retries": self._metrics.get("retries", 0),
            "throttle_waits": self._metrics.get("throttle_waits", 0),
            "ssrf_blocks": self._metrics.get("ssrf_blocks", 0),
        }

# Global shared client instance
_shared_client: Optional[SharedHTTPClient] = None

def get_shared_http_client() -> SharedHTTPClient:
    """Get or create the global shared HTTP client instance."""
    global _shared_client
    if _shared_client is None:
        _shared_client = SharedHTTPClient()
    return _shared_client

@asynccontextmanager
async def get_http_client(
    *,
    timeout: float = 30.0,
    verify: bool = False,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
    use_cache: bool = True,
    cache_ttl: Optional[int] = None
) -> AsyncIterator[httpx.AsyncClient]:
    """Enhanced HTTP client context manager with caching and pooling.
    
    This maintains backward compatibility while providing access to the shared client.
    """
    # For backward compatibility, still yield an httpx.AsyncClient
    # but use the shared client internally for actual requests
    config = {
        "timeout": timeout,
        "verify": verify,
        "follow_redirects": follow_redirects,
        "headers": headers or {}
    }
    
    # Create a wrapper client that delegates to shared client
    class WrappedClient:
        def __init__(self, shared_client: SharedHTTPClient, config: Dict):
            self.shared_client = shared_client
            self.config = config
        
        async def get(self, url: str, **kwargs) -> httpx.Response:
            merged_headers = {**self.config.get('headers', {}), **kwargs.get('headers', {})}
            return await self.shared_client.get(url, headers=merged_headers, **kwargs)
        
        async def post(self, url: str, **kwargs) -> httpx.Response:
            merged_headers = {**self.config.get('headers', {}), **kwargs.get('headers', {})}
            return await self.shared_client.post(url, headers=merged_headers, **kwargs)
        
        async def head(self, url: str, **kwargs) -> httpx.Response:
            merged_headers = {**self.config.get('headers', {}), **kwargs.get('headers', {})}
            return await self.shared_client.head(url, headers=merged_headers, **kwargs)
        
        async def options(self, url: str, **kwargs) -> httpx.Response:
            merged_headers = {**self.config.get('headers', {}), **kwargs.get('headers', {})}
            return await self.shared_client.options(url, headers=merged_headers, **kwargs)
        
        async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
            merged_headers = {**self.config.get('headers', {}), **kwargs.get('headers', {})}
            return await self.shared_client.request(method, url, headers=merged_headers, **kwargs)
    
    shared_client = get_shared_http_client()
    wrapped_client = WrappedClient(shared_client, config)
    
    try:
        yield wrapped_client
    finally:
        # Cleanup handled by shared client
        pass
