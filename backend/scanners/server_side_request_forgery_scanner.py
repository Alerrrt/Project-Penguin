import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx
from urllib.parse import urlparse, urlencode, parse_qs
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from backend.scanners.base_scanner import BaseScanner
from ..config_types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog
from backend.utils import get_http_client
from backend.utils.crawler import seed_urls

logger = logging.getLogger(__name__)

class ServerSideRequestForgeryScanner(BaseScanner):
    """
    A scanner module for detecting Server-Side Request Forgery (SSRF) vulnerabilities.
    """

    metadata = {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Detects SSRF vulnerabilities by sending controlled payloads to endpoints.",
        "owasp_category": "A10:2021 - Server-Side Request Forgery (SSRF)",
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
        Asynchronously sends controlled payloads to detect SSRF endpoints.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for detected SSRF vulnerabilities.
        """
        findings: List[Dict] = []
        target_url = target
        logger.info(f"Starting Server-Side Request Forgery scan for {target_url}.")

        # Safe, non-destructive SSRF hints: do not use OOB by default; no real internal impact.
        ssrf_payloads = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "file:///etc/passwd",
            "file:///C:/Windows/System32/drivers/etc/hosts",
        ]

        timeout = float(options.get("timeout", 10))
        use_seeds = bool(options.get("use_seeds", True))
        max_urls = int(options.get("max_urls", 6))

        async with get_http_client(follow_redirects=True, timeout=timeout) as client:
            tasks = []
            urls_to_test = [target_url]
            if use_seeds:
                try:
                    urls_to_test.extend(await seed_urls(target_url, max_urls=max_urls))
                except Exception:
                    pass

            for base in urls_to_test:
                parsed_url = urlparse(base)
                query_params = parse_qs(parsed_url.query)
                for param, values in query_params.items():
                    for payload in ssrf_payloads:
                        new_query = query_params.copy()
                        new_query[param] = [payload]
                        test_url = parsed_url._replace(query=urlencode(new_query, doseq=True)).geturl()
                        tasks.append(self._check_ssrf(client, test_url, payload, param))

            common_ssrf_params = ["url", "image", "file", "path", "link"]
            for base in urls_to_test:
                parsed_url = urlparse(base)
                query_params = parse_qs(parsed_url.query)
                for param in common_ssrf_params:
                    if param not in query_params:
                        for payload in ssrf_payloads:
                            new_query = query_params.copy()
                            new_query[param] = [payload]
                            test_url = parsed_url._replace(query=urlencode(new_query, doseq=True)).geturl()
                            tasks.append(self._check_ssrf(client, test_url, payload, param))

            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    findings.append(result)

        logger.info(f"Finished Server-Side Request Forgery scan for {target_url}.")
        return findings

    async def _check_ssrf(self, client: httpx.AsyncClient, test_url: str, payload: str, param: str) -> Optional[Dict]:
        try:
            response = await client.get(test_url)
            if "root:x:0:0:" in response.text.lower() or "access denied" in response.text.lower() or "metadata" in response.text.lower():
                return {
                    "type": "ssrf",
                    "severity": Severity.CRITICAL,
                    "title": "Potential SSRF Vulnerability",
                    "description": f"Potential SSRF vulnerability detected by injecting '{payload}' into parameter '{param}'. Server responded with content that suggests internal resource access or error.",
                    "evidence": {
                        "test_url": test_url,
                        "parameter": param,
                        "injected_payload": payload,
                        "response_status": response.status_code,
                        "response_snippet": response.text[:200]
                    },
                    "owasp_category": OwaspCategory.SERVER_SIDE_REQUEST_FORGERY_SSRF,
                    "recommendation": "Implement strict input validation for all URLs and paths provided by users. Whitelist allowed schemes, hosts, and protocols. Do not allow redirects to arbitrary URLs.",
                    "affected_url": test_url
                }
        except httpx.RequestError as e:
            if isinstance(e, httpx.ConnectError) and ("127.0.0.1" in payload or "localhost" in payload):
                logger.warning(f"Possible SSRF: Connection error to internal payload {payload} for {test_url}", extra={"error": str(e)})
                return {
                    "type": "ssrf_connection_error",
                    "severity": Severity.HIGH,
                    "title": "Server-Side Request Forgery (SSRF) - Connection Error",
                    "description": f"Possible SSRF vulnerability detected. An attempt to connect to internal host '{payload}' via parameter '{param}' resulted in a connection error, which could indicate the server tried to access it internally.",
                    "evidence": {
                        "test_url": test_url,
                        "parameter": param,
                        "injected_payload": payload,
                        "error_message": str(e)
                    },
                    "owasp_category": OwaspCategory.SERVER_SIDE_REQUEST_FORGERY_SSRF,
                    "recommendation": "Implement strict input validation for all URLs and paths provided by users. Whitelist allowed schemes, hosts, and protocols. Do not allow redirects to arbitrary URLs.",
                    "affected_url": test_url
                }
            logger.error(f"Error checking SSRF for {test_url}", extra={"error": str(e)})
        return None

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "SSRF Scanner Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
