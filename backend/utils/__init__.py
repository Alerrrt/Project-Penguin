# Import the enhanced HTTP client functionality
from .http_client import get_http_client, get_shared_http_client, SharedHTTPClient

# Legacy imports for backward compatibility
import httpx
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional, Dict

_DEFAULT_HEADERS = {
    "User-Agent": "ProjectEchoScanner/2.0 (+https://github.com/Alerrrt/Project-Echo)"
}

# Keep the old function for backward compatibility, but it now uses the enhanced client
@asynccontextmanager
async def get_http_client_legacy(
    *,
    timeout: float = 30.0,
    verify: bool = False,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> AsyncIterator[httpx.AsyncClient]:
    """Legacy HTTP client context manager - now delegates to enhanced client.
    
    This maintains backward compatibility while providing access to the shared client.
    """
    async with get_http_client(
        timeout=timeout,
        verify=verify,
        follow_redirects=follow_redirects,
        headers=headers
    ) as client:
        yield client
