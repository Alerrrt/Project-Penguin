import asyncio
from typing import List, Dict, Any
from datetime import datetime
import logging

from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from backend.utils import get_http_client

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.config_types.models import ScanInput, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class InsufficientLoggingAndMonitoringScanner(BaseScanner):
    """
    A scanner module for detecting insufficient logging and monitoring vulnerabilities.
    """

    metadata = {
        "name": "Insufficient Logging and Monitoring",
        "description": "Detects missing security headers and improper error handling that may indicate insufficient logging and monitoring.",
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
        Asynchronously checks for insufficient logging and monitoring vulnerabilities.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for detected insufficient logging and monitoring issues.
        """
        findings: List[Dict] = []
        target_url = target
        logger.info(f"Starting Insufficient Logging and Monitoring scan for {target_url}")

        # Test cases for insufficient logging
        test_cases = [
            {
                "path": "/api/login",
                "method": "POST",
                "data": {"username": "test", "password": "test123"},
                "expected_status": 401,
                "description": "Failed login attempt"
            },
            {
                "path": "/api/users/1",
                "method": "DELETE",
                "data": None,
                "expected_status": 403,
                "description": "Unauthorized deletion attempt"
            },
            {
                "path": "/api/admin",
                "method": "GET",
                "data": None,
                "expected_status": 403,
                "description": "Unauthorized admin access attempt"
            }
        ]

        async with get_http_client(follow_redirects=True, timeout=30) as client:
            for test_case in test_cases:
                try:
                    url = f"{target_url.rstrip('/')}/{test_case['path'].lstrip('/')}"
                    
                    if test_case['method'] == 'POST':
                        response = await client.post(url, json=test_case['data'])
                    elif test_case['method'] == 'DELETE':
                        response = await client.delete(url)
                    else:
                        response = await client.get(url)

                    # Check if the response indicates proper error handling
                    if response.status_code == test_case['expected_status']:
                        # Check for security headers that might indicate logging
                        security_headers = {
                            "x-content-type-options": "nosniff",
                            "x-frame-options": "DENY",
                            "content-security-policy": "default-src 'self'"
                        }

                        missing_headers = []
                        for header, value in security_headers.items():
                            if header not in response.headers:
                                missing_headers.append(header)

                        if missing_headers:
                            findings.append({
                                "type": "insufficient_security_headers",
                                "severity": Severity.MEDIUM,
                                "title": "Insufficient Security Headers",
                                "description": f"Missing security headers for {test_case['description']}.",
                                "evidence": {
                                    "test_case": test_case['description'],
                                    "missing_headers": missing_headers,
                                    "response_status": response.status_code
                                },
                                "owasp_category": OwaspCategory.LOGGING_AND_MONITORING_FAILURES,
                                "recommendation": "Implement proper security headers and ensure all security events are logged. Consider implementing a Web Application Firewall (WAF) for additional monitoring.",
                                "affected_url": url
                            })

                except Exception as e:
                    logger.error(f"Error testing logging", extra={
                        "url": url,
                        "test_case": test_case['description'],
                        "error": str(e)
                    })
                except Exception as e:
                    logger.error(f"Unexpected error during logging scan", extra={
                        "url": url,
                        "test_case": test_case['description'],
                        "error": str(e)
                    }, exc_info=True)

        logger.info(f"Completed Insufficient Logging and Monitoring scan for {target_url}. Found {len(findings)} issues.")
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Insufficient Logging and Monitoring Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("insufficient_logging_and_monitoring", InsufficientLoggingAndMonitoringScanner) 
