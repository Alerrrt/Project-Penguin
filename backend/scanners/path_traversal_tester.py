import asyncio
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
import httpx
from backend.utils import get_http_client
from urllib.parse import urljoin
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from .base_scanner import BaseScanner
from ..config_types.models import ScanInput, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class PathTraversalTesterScanner(BaseScanner):
    """
    A scanner module for detecting path traversal vulnerabilities.
    """

    metadata = {
        "name": "Path Traversal Scanner",
        "description": "Detects path traversal vulnerabilities by testing various payloads and parameters.",
        "owasp_category": "A01:2021 - Broken Access Control",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        try:
            return await self._perform_scan(scan_input.target, scan_input.options or {})
        except Exception as e:
            logger.error(f"Path Traversal Tester scan failed: {e}", exc_info=True)
            return [self._create_error_finding(f"Path Traversal Tester scan failed: {e}")]

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Asynchronously appends payloads to detect directory traversal flaws.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for detected path traversal vulnerabilities.
        """
        findings: List[Dict] = []
        target_url = target
        logger.info("Starting Path Traversal scan", extra={"target": target_url})

        # Common path traversal payloads for various OS
        path_traversal_payloads = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", # URL encoded
            "..%2f..%2f..%2f..%2fwindows/win.ini", # Double URL encoded
            "....//....//....//....//etc/passwd", # Unicode bypass
            "/etc/passwd%00.jpg", # Null byte bypass
            "\x00..\x00..\x00/etc/passwd", # Non-standard encoding
            # Add more variations and OS-specific paths
        ]

        # Common parameters that might be vulnerable
        common_params = ["file", "path", "page", "doc", "view", "filename"]

        try:
            async with get_http_client(follow_redirects=True, timeout=30) as client:
                tasks = []
                for param in common_params:
                    for payload in path_traversal_payloads:
                        # Attempt to inject into query parameters
                        test_url_query = f"{target_url}?{param}={payload}"
                        tasks.append(self._check_path_traversal(client, test_url_query, param, payload))

                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        logger.error("Error during path traversal check", extra={
                            "error": str(result)
                        }, exc_info=True)
                    elif result:
                        findings.append(result)

        except Exception as e:
            logger.error("Unexpected error during scan", extra={
                "target": target_url,
                "error": str(e)
            }, exc_info=True)

        logger.info("Completed Path Traversal scan", extra={
            "target": target_url,
            "findings_count": len(findings)
        })
        return findings

    async def _check_path_traversal(self, client: httpx.AsyncClient, test_url: str, param: str, payload: str) -> Optional[Dict]:
        """
        Checks for path traversal vulnerability using a specific payload.

        Args:
            client: The HTTP client to use for requests.
            test_url: The URL to test.
            param: The parameter being tested.
            payload: The payload being injected.

        Returns:
            A finding dictionary if vulnerability is detected, None otherwise.
        """
        try:
            response = await client.get(test_url)

            # Check for content that suggests file exposure
            if "root:x:0:0:" in response.text.lower() or "for 16-bit app support" in response.text.lower():
                logger.info("Path traversal vulnerability detected", extra={
                    "url": test_url,
                    "param": param,
                    "payload": payload
                })
                return {
                    "type": "path_traversal",
                    "severity": Severity.HIGH,
                    "title": "Path Traversal Vulnerability Detected",
                    "description": f"Potential Path Traversal vulnerability detected by injecting '{payload}' into parameter '{param}'. Server responded with content that suggests file exposure.",
                    "evidence": {
                        "test_url": test_url,
                        "parameter": param,
                        "injected_payload": payload,
                        "response_status": response.status_code,
                        "response_snippet": response.text[:200]
                    },
                    "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                    "recommendation": "Implement strict input validation and sanitization for all file and path-related inputs. Use whitelisting for allowed file types and directories. Do not concatenate user input directly into file paths.",
                    "affected_url": test_url
                }

        except httpx.RequestError as e:
            logger.warning("Request error during path traversal check", extra={
                "url": test_url,
                "error": str(e)
            })
        except Exception as e:
            logger.error("Unexpected error during path traversal check", extra={
                "url": test_url,
                "error": str(e)
            }, exc_info=True)

        return None

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Path Traversal Tester Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
