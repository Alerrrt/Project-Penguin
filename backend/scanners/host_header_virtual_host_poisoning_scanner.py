import asyncio
import uuid
import httpx
from typing import List, Optional, Dict, Any
from backend.utils import get_http_client
from urllib.parse import urlparse
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from backend.scanners.base_scanner import BaseScanner
from ..config_types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog

logger = logging.getLogger(__name__)

class HostHeaderVirtualHostPoisoningScanner(BaseScanner):
    """
    A scanner module for detecting Host Header and Virtual Host Poisoning vulnerabilities.
    """

    metadata = {
        "name": "Host Header Virtual Host Poisoning",
        "description": "Detects host header injection and virtual host poisoning vulnerabilities.",
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
        Asynchronously swaps the Host: header to evil.com or 127.0.0.1 and watches for odd behavior.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for detected Host Header/Virtual Host Poisoning vulnerabilities.
        """
        findings: List[Dict] = []
        target_url = target
        logger.info(f"Starting Host Header and Virtual Host Poisoning scan for {target_url}.")

        # Common malicious Host headers to test
        evil_hosts = [
            "evil.com",
            "127.0.0.1",
            "localhost",
            "example.com:8080",
            "www.attacker.com",
            f"{urlparse(target_url).netloc}:8080",
            "[::1]",
        ]

        async with get_http_client(follow_redirects=True, timeout=10) as client:
            tasks = []
            for evil_host in evil_hosts:
                tasks.append(self._check_host_header_poisoning(client, target_url, evil_host))

            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    findings.append(result)

        logger.info(f"Finished Host Header and Virtual Host Poisoning scan for {target_url}.")
        return findings

    async def _check_host_header_poisoning(self, client: httpx.AsyncClient, target_url: str, evil_host: str) -> Optional[Dict]:
        try:
            headers = {"Host": evil_host}
            response = await client.get(target_url, headers=headers)

            if evil_host in response.text or (response.headers.get("location") and evil_host in response.headers["location"]):
                if response.status_code == 200 or 300 <= response.status_code < 400:
                    return {
                        "type": "host_header_injection",
                        "severity": Severity.HIGH,
                        "title": "Host Header Injection/Virtual Host Poisoning",
                        "description": f"Potential Host Header Injection or Virtual Host Poisoning detected. The injected Host header '{evil_host}' was reflected in the response or caused an unexpected redirect.",
                        "evidence": {
                            "test_url": target_url,
                            "injected_host_header": evil_host,
                            "response_status": response.status_code,
                            "response_snippet": response.text[:200],
                            "location_header": response.headers.get("location"),
                            "reflection_found": True
                        },
                        "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                        "recommendation": "Ensure the application explicitly validates the Host header against a whitelist of allowed domains or uses the original request's Host header only for internal routing, not for generating absolute URLs or redirects. Prevent caching mechanisms from caching responses based on arbitrary Host headers.",
                        "affected_url": target_url
                    }
            elif response.status_code == 400:
                logger.debug(f"Received 400 Bad Request for Host: {evil_host} on {target_url}")

        except httpx.RequestError as e:
            logger.error(f"Error checking Host Header poisoning for {target_url}", extra={
                "host": evil_host,
                "error": str(e)
            })
        return None

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Host Header/Virtual Host Poisoning Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
