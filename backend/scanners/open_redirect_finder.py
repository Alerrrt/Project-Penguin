import asyncio
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
import httpx
from backend.utils import get_http_client
from urllib.parse import urljoin, urlparse
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from .base_scanner import BaseScanner
from ..config_types.models import ScanInput, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class OpenRedirectFinderScanner(BaseScanner):
    """
    A scanner module for detecting open redirect vulnerabilities.
    """

    metadata = {
        "name": "Open Redirect Scanner",
        "description": "Detects open redirect vulnerabilities by testing various redirect parameters and payloads.",
        "owasp_category": "A01:2021 - Broken Access Control",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        start_time = datetime.now()
        scan_id = f"{self.__class__.__name__}_{start_time.strftime('%Y%m%d_%H%M%S')}"
        try:
            logger.info("Scan started", extra={
                "scanner": self.__class__.__name__,
                "scan_id": scan_id,
                "target": scan_input.target,
                "options": scan_input.options
            })
            results = await self._perform_scan(scan_input.target, scan_input.options or {})
            self._update_metrics(True, start_time)
            logger.info("Scan completed", extra={
                "scanner": self.__class__.__name__,
                "scan_id": scan_id,
                "target": scan_input.target,
                "result_count": len(results)
            })
            return results
        except Exception as e:
            self._update_metrics(False, start_time)
            logger.error("Scan failed", extra={
                "scanner": self.__class__.__name__,
                "scan_id": scan_id,
                "target": scan_input.target,
                "error": str(e)
            }, exc_info=True)
            raise

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Asynchronously crawls the target and injects payloads to detect unsafe redirects.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for detected open redirects.
        """
        findings: List[Dict] = []
        base_url = target
        logger.info(f"Starting Open Redirect scan for {base_url}")

        # Simple example payloads and common redirect parameters
        redirect_params = ["next", "redirect", "url", "dest", "continue", "return_to"]
        evil_url = "https://evil.com/malicious_page"

        async with get_http_client(follow_redirects=False, timeout=30) as client:
            # Fetch the main page to find potential links/forms
            try:
                response = await client.get(base_url)
                response.raise_for_status()
                # A more advanced scanner would parse HTML to find all links and form actions
                # For now, we'll just test the base URL with common redirect parameters

                tasks = []
                for param in redirect_params:
                    test_url = f"{base_url}?{param}={evil_url}"
                    tasks.append(self._check_redirect(client, test_url, param, evil_url))

                results = await asyncio.gather(*tasks)
                for result in results:
                    if result:
                        findings.append(result)

            except httpx.RequestError as e:
                logger.error(f"Error fetching base URL", extra={
                    "url": base_url,
                    "error": str(e)
                })
            except Exception as e:
                logger.error(f"Unexpected error during scan", extra={
                    "url": base_url,
                    "error": str(e)
                }, exc_info=True)

        logger.info(f"Completed Open Redirect scan for {base_url}. Found {len(findings)} issues.")
        return findings

    async def _check_redirect(self, client, test_url: str, param: str, evil_url: str) -> Optional[Dict]:
        try:
            response = await client.get(test_url)
            # Check for 3xx redirect status codes
            if 300 <= response.status_code < 400:
                location = response.headers.get("location")
                if location and evil_url in location: # Check if the redirect points to our evil URL
                    return {
                        "type": "open_redirect",
                        "severity": Severity.HIGH,
                        "title": "Open Redirect Vulnerability Detected",
                        "description": f"Open redirect vulnerability detected. The URL redirects to an external malicious site: {location}",
                        "evidence": {
                            "test_url": test_url,
                            "parameter": param,
                            "injected_payload": evil_url,
                            "redirect_status": response.status_code,
                            "redirect_location": location
                        },
                        "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                        "recommendation": "Ensure all redirect functionalities validate the destination URL against a whitelist of allowed domains. Do not rely on blacklisting or user-supplied input directly for redirects.",
                        "affected_url": test_url
                    }
        except httpx.RequestError as e:
            logger.error(f"Error checking redirect", extra={
                "test_url": test_url,
                "error": str(e)
            })
        except Exception as e:
            logger.error(f"Unexpected error during redirect check", extra={
                "test_url": test_url,
                "error": str(e)
            }, exc_info=True)
        return None

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Open Redirect Finder Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
