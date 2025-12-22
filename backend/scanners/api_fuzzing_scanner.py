import asyncio
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
import json
from urllib.parse import urljoin
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging
from backend.utils import get_http_client

from .base_scanner import BaseScanner
from ..config_types.models import ScanInput, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class ApiFuzzingScanner(BaseScanner):
    """
    A scanner module for fuzzing JSON API endpoints to detect unhandled errors.
    """

    metadata = {
        "name": "API Fuzzing Scanner",
        "description": "Detects vulnerabilities in API endpoints by fuzzing with various payloads.",
        "owasp_category": "A09:2021 - Security Logging and Monitoring Failures",
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
        Asynchronously fuzzes JSON API endpoints with various payloads.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for detected API vulnerabilities.
        """
        findings: List[Dict] = []
        target_url = target
        logger.info(f"Starting API Fuzzing scan for {target_url}")

        # Simple placeholder fuzzing payloads
        fuzzing_payloads = {
            "string_overflow": "A" * 5000,
            "sql_injection": "' OR 1=1-- ",
            "xss": "<script>alert('XSS')</script>",
            "command_injection": "; ls -la;",
            "format_string": "%n%n%n%n%n%n%n%n%n%n%n%n",
            "negative_number": -1,
            "large_number": 99999999999999999999,
            "empty_value": "",
            "null_value": None,
        }

        # Discover JSON endpoints (very basic placeholder)
        # A real scanner would crawl, analyze Swagger/OpenAPI docs, or use a proxy.
        potential_json_endpoints = [
            f"{target_url}/api/v1/data",
            f"{target_url}/api/items",
            f"{target_url}/users/create",
        ]

        async with get_http_client(follow_redirects=True, timeout=30) as client:
            tasks = []
            for endpoint in potential_json_endpoints:
                for payload_name, payload_value in fuzzing_payloads.items():
                    test_data = {"test_field": payload_value} # Simulate a generic JSON field
                    if payload_value is None:
                        # For None payload, ensure it's handled as JSON null
                        json_payload = json.dumps({"test_field": None})
                    else:
                        json_payload = json.dumps(test_data)

                    headers = {"Content-Type": "application/json"}
                    tasks.append(self._fuzz_endpoint(client, endpoint, json_payload, headers, payload_name))

            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    findings.append(result)

        logger.info(f"Completed API Fuzzing scan for {target_url}. Found {len(findings)} issues.")
        return findings

    async def _fuzz_endpoint(self, client: get_http_client, url: str, payload: str, headers: Dict[str, str], payload_type: str) -> Optional[Dict]:
        try:
            response = await client.post(url, headers=headers, content=payload, timeout=5)
            
            # Look for indicators of unhandled errors or unexpected behavior
            if response.status_code >= 500 or "error" in response.text.lower() or "exception" in response.text.lower():
                return {
                    "type": "api_fuzzing_vulnerability",
                    "severity": Severity.MEDIUM,
                    "title": f"API Fuzzing: Unhandled Error ({payload_type})",
                    "description": f"API endpoint '{url}' responded with an error (Status: {response.status_code}) or unusual content when fuzzed with '{payload_type}' payload. This could indicate a vulnerability or poor error handling.",
                    "evidence": {
                        "test_url": url,
                        "payload_type": payload_type,
                        "sent_payload_snippet": payload[:100],
                        "response_status": response.status_code,
                        "response_snippet": response.text[:200]
                    },
                    "owasp_category": OwaspCategory.SECURITY_LOGGING_AND_MONITORING_FAILURES,
                    "recommendation": "Implement robust input validation and error handling for all API endpoints. Avoid exposing sensitive error messages or stack traces.",
                    "affected_url": url
                }
        except Exception as e:
            # Log at debug level to avoid spam, only log unique errors
            error_key = f"{type(e).__name__}:{url}"
            if not hasattr(self, '_logged_errors'):
                self._logged_errors = set()
            if error_key not in self._logged_errors:
                self._logged_errors.add(error_key)
                logger.debug(f"API fuzzing error for {url}: {type(e).__name__}")
        return None 

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "API Fuzzing Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
