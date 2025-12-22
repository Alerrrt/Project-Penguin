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

class SecurityMisconfigurationScanner(BaseScanner):
    """
    A scanner module for detecting security misconfigurations.
    """

    metadata = {
        "name": "Security Misconfiguration",
        "description": "Detects common security misconfigurations such as exposed files and missing security headers.",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="security_misconfiguration_scanner")
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
        Perform the actual security misconfiguration scan.

        Args:
            target: Target URL to scan
            options: Scan options including timeout

        Returns:
            List of findings containing security misconfigurations
        """
        findings = []
        timeout = options.get('timeout', 10)
        
        async with get_http_client(timeout=timeout) as client:
            try:
                response = await client.get(target)
                headers = response.headers
                
                # Check for missing security headers
                security_headers = {
                    'Strict-Transport-Security': 'HSTS header missing',
                    'X-Content-Type-Options': 'X-Content-Type-Options header missing',
                    'X-Frame-Options': 'X-Frame-Options header missing',
                    'X-XSS-Protection': 'X-XSS-Protection header missing',
                    'Content-Security-Policy': 'Content-Security-Policy header missing',
                    'Referrer-Policy': 'Referrer-Policy header missing'
                }
                
                for header, message in security_headers.items():
                    if header not in headers:
                        findings.append({
                            "type": "missing_security_header",
                            "severity": Severity.MEDIUM,
                            "title": f"Missing Security Header: {header}",
                            "description": message,
                            "evidence": {
                                "url": target,
                                "missing_header": header
                            },
                            "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                            "recommendation": f"Implement the {header} header to enhance security."
                        })
                
                # Check for server information disclosure
                server_header = headers.get('Server', '')
                if server_header:
                    findings.append({
                        "type": "server_information_disclosure",
                        "severity": Severity.LOW,
                        "title": "Server Information Disclosure",
                        "description": f"Server header reveals information: {server_header}",
                        "evidence": {
                            "url": target,
                            "server_header": server_header
                        },
                        "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                        "recommendation": "Remove or modify the Server header to prevent information disclosure."
                    })
                
                # Check for directory listing
                if "Index of" in response.text or "Directory Listing For" in response.text:
                    findings.append({
                        "type": "directory_listing_enabled",
                        "severity": Severity.MEDIUM,
                        "title": "Directory Listing Enabled",
                        "description": "Directory listing is enabled, potentially exposing sensitive files",
                        "evidence": {
                            "url": target,
                            "response_preview": response.text[:200]
                        },
                        "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                        "recommendation": "Disable directory listing on the web server."
                    })
                
            except Exception as e:
                logger.warning(
                    f"Error scanning target {target}",
                    extra={
                        "target": target,
                        "error": str(e)
                    }
                )
                
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Security Misconfiguration Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("security_misconfiguration", SecurityMisconfigurationScanner) 
