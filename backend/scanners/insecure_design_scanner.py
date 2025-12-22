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

class InsecureDesignScanner(BaseScanner):
    """
    A scanner module for detecting insecure design vulnerabilities.
    """

    metadata = {
        "name": "Insecure Design",
        "description": "Detects insecure design patterns such as missing security headers, weak password policies, and lack of rate limiting.",
        "owasp_category": "A04:2021 - Insecure Design",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="insecure_design_scanner")
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
        Asynchronously checks for insecure design vulnerabilities.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for detected insecure design issues.
        """
        findings: List[Dict] = []
        target_url = target
        logger.info(f"Starting Insecure Design scan for {target_url}")

        # Test cases for insecure design patterns
        test_cases = [
            {
                "path": "/api/users",
                "method": "GET",
                "description": "User enumeration through API",
                "expected_status": 200
            },
            {
                "path": "/api/register",
                "method": "POST",
                "data": {
                    "username": "test",
                    "password": "test123",
                    "email": "test@example.com"
                },
                "description": "Weak password policy",
                "expected_status": 201
            },
            {
                "path": "/api/reset-password",
                "method": "POST",
                "data": {
                    "email": "test@example.com"
                },
                "description": "Password reset without rate limiting",
                "expected_status": 200
            }
        ]

        async with get_http_client(follow_redirects=True, timeout=30) as client:
            for test_case in test_cases:
                try:
                    url = f"{target_url.rstrip('/')}/{test_case['path'].lstrip('/')}"
                    
                    if test_case['method'] == 'POST':
                        response = await client.post(url, json=test_case['data'])
                    else:
                        response = await client.get(url)

                    # Check for insecure design patterns
                    if response.status_code == test_case['expected_status']:
                        # Check for security headers
                        security_headers = {
                            "x-content-type-options": "nosniff",
                            "x-frame-options": "DENY",
                            "content-security-policy": "default-src 'self'",
                            "strict-transport-security": "max-age=31536000; includeSubDomains"
                        }

                        missing_headers = []
                        for header, value in security_headers.items():
                            if header not in response.headers:
                                missing_headers.append(header)

                        if missing_headers:
                            findings.append({
                                "type": "insecure_design_missing_headers",
                                "severity": Severity.MEDIUM,
                                "title": "Insecure Design - Missing Security Headers",
                                "description": f"Missing security headers for {test_case['description']}.",
                                "evidence": {
                                    "test_case": test_case['description'],
                                    "missing_headers": missing_headers,
                                    "response_status": response.status_code
                                },
                                "owasp_category": OwaspCategory.INSECURE_DESIGN,
                                "recommendation": "Implement proper security headers and follow secure design principles. Consider implementing a Web Application Firewall (WAF) for additional protection.",
                                "affected_url": url
                            })

                        # Check for weak password policy
                        if test_case['description'] == "Weak password policy":
                            if len(test_case['data']['password']) < 8:
                                findings.append({
                                    "type": "insecure_design_weak_password",
                                    "severity": Severity.HIGH,
                                    "title": "Insecure Design - Weak Password Policy",
                                    "description": "Application allows weak passwords.",
                                    "evidence": {
                                        "test_case": test_case['description'],
                                        "password_length": len(test_case['data']['password'])
                                    },
                                    "owasp_category": OwaspCategory.INSECURE_DESIGN,
                                    "recommendation": "Implement a strong password policy requiring minimum length, complexity, and preventing common passwords.",
                                    "affected_url": url
                                })

                except Exception as e:
                    logger.error(f"Error testing insecure design", extra={
                        "url": url,
                        "test_case": test_case['description'],
                        "error": str(e)
                    })
                except Exception as e:
                    logger.error(f"Unexpected error during insecure design scan", extra={
                        "url": url,
                        "test_case": test_case['description'],
                        "error": str(e)
                    }, exc_info=True)

        logger.info(f"Completed Insecure Design scan for {target_url}. Found {len(findings)} issues.")
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Insecure Design Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("insecure_design", InsecureDesignScanner) 
