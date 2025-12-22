import asyncio
import uuid
from typing import List, Dict, Any
from backend.utils import get_http_client
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.config_types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog

logger = logging.getLogger(__name__)

class BrokenAuthenticationScanner(BaseScanner):
    """
    A scanner module for detecting broken authentication vulnerabilities.
    """

    metadata = {
        "name": "Broken Authentication",
        "description": "Detects missing authentication and weak credentials on common authentication endpoints.",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="broken_authentication_scanner")
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        """
        Perform a security scan with circuit breaker protection.
        
        Args:
            scan_input: The input for the scan, including target and options.
            
        Returns:
            List of scan results
        """
        start_time = datetime.now()
        scan_id = f"{self.__class__.__name__}_{start_time.strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Log scan start
            logger.info(
                "Scan started",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "options": scan_input.options
                }
            )
            
            # Perform scan
            results = await self._perform_scan(scan_input.target, scan_input.options or {})
            
            # Update metrics
            self._update_metrics(True, start_time)
            
            # Log scan completion
            logger.info(
                "Scan completed",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "result_count": len(results)
                }
            )
            
            return results
            
        except Exception as e:
            # Update metrics
            self._update_metrics(False, start_time)
            
            # Log error
            logger.error(
                "Scan failed",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "error": str(e)
                },
                exc_info=True
            )
            raise

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Perform the actual broken authentication scan.
        
        Args:
            target: Target URL to scan
            options: Scan options including timeout and credentials
            
        Returns:
            List of findings containing authentication vulnerabilities
        """
        findings = []
        timeout = options.get('timeout', 10)
        
        # Common authentication endpoints to test
        auth_endpoints = options.get('endpoints', [
            "/login",
            "/auth",
            "/signin",
            "/api/auth",
            "/api/login",
            "/api/v1/auth",
            "/api/v1/login"
        ])

        # Common weak credentials to test
        weak_credentials = options.get('credentials', [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "test", "password": "test"},
            {"username": "user", "password": "user"}
        ])

        async with get_http_client(timeout=timeout) as client:
            for endpoint in auth_endpoints:
                auth_url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
                
                try:
                    # Test for missing authentication
                    response = await client.get(auth_url)
                    if response.status_code == 200:
                        findings.append({
                            "type": "missing_authentication",
                            "severity": Severity.HIGH,
                            "title": "Missing Authentication",
                            "description": f"Endpoint '{endpoint}' is accessible without authentication",
                            "evidence": {
                                "url": auth_url,
                                "status_code": response.status_code,
                                "response_length": len(response.text)
                            },
                            "owasp_category": OwaspCategory.IDENTIFICATION_AND_AUTHENTICATION_FAILURES,
                            "recommendation": "Implement proper authentication checks for all sensitive endpoints. Ensure authentication is required before accessing protected resources."
                        })

                    # Test for weak credentials
                    for creds in weak_credentials:
                        try:
                            response = await client.post(
                                auth_url,
                                json=creds,
                                headers={"Content-Type": "application/json"}
                            )
                            
                            # Check if login was successful
                            if response.status_code == 200 and "token" in response.text.lower():
                                findings.append({
                                    "type": "weak_credentials",
                                    "severity": Severity.HIGH,
                                    "title": "Weak Credentials Accepted",
                                    "description": f"Endpoint '{endpoint}' accepts weak credentials",
                                    "evidence": {
                                        "url": auth_url,
                                        "credentials": creds,
                                        "status_code": response.status_code
                                    },
                                    "owasp_category": OwaspCategory.IDENTIFICATION_AND_AUTHENTICATION_FAILURES,
                                    "recommendation": "Implement strong password policies and prevent the use of common or weak credentials. Consider implementing rate limiting and account lockout mechanisms."
                                })
                        except Exception as e:
                            logger.warning(
                                f"Error testing credentials for {auth_url}",
                                extra={
                                    "url": auth_url,
                                    "credentials": creds,
                                    "error": str(e)
                                }
                            )
                            continue

                except Exception as e:
                    logger.warning(
                        f"Error testing authentication for {auth_url}",
                        extra={
                            "url": auth_url,
                            "error": str(e)
                        }
                    )
                    continue
                    
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Broken Authentication Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("broken_authentication", BrokenAuthenticationScanner) 
