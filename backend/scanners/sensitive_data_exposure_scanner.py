import asyncio
import uuid
import re
from typing import List, Dict, Any
import httpx
from backend.utils import get_http_client
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.config_types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog

logger = get_context_logger(__name__)

class SensitiveDataExposureScanner(BaseScanner):
    """
    A scanner module for detecting sensitive data exposure vulnerabilities.
    """

    metadata = {
        "name": "Sensitive Data Exposure",
        "description": "Detects exposure of sensitive data such as emails, API keys, and credentials in responses and headers.",
        "owasp_category": "A04:2021 - Insecure Design",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    # Regular expressions for detecting sensitive data patterns
    SENSITIVE_PATTERNS = {
        "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "ssn": r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        "api_key": r"(?i)(api[_-]?key|apikey)[_-]?[a-z0-9]{32,}",
        "password": r"(?i)(password|passwd|pwd)[_-]?[a-z0-9]{8,}",
        "jwt": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "private_key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="sensitive_data_exposure_scanner")
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
        Asynchronously checks for sensitive data exposure vulnerabilities.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for detected sensitive data exposures.
        """
        findings: List[Dict] = []
        target_url = target
        logger.info(f"Starting Sensitive Data Exposure scan for {target_url}.")

        async with get_http_client(follow_redirects=True, timeout=10) as client:
            try:
                # Get the main page content
                response = await client.get(target_url)
                content = response.text

                # Check for sensitive data patterns
                for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        # Mask the sensitive data in the finding
                        sensitive_data = match.group(0)
                        masked_data = self._mask_sensitive_data(sensitive_data, pattern_name)
                        
                        findings.append({
                            "type": "sensitive_data_exposure",
                            "severity": Severity.HIGH,
                            "title": "Sensitive Data Exposure",
                            "description": f"Potential {pattern_name.replace('_', ' ').title()} exposure detected in the response.",
                            "evidence": {
                                "pattern_type": pattern_name,
                                "masked_data": masked_data,
                                "context": content[max(0, match.start()-20):min(len(content), match.end()+20)]
                            },
                            "owasp_category": OwaspCategory.INSECURE_DESIGN,
                            "recommendation": "Implement proper data protection measures. Ensure sensitive data is encrypted in transit and at rest. Follow the principle of least privilege and only expose necessary data.",
                            "affected_url": target_url
                        })

                # Check response headers for sensitive information
                headers = response.headers
                sensitive_headers = {
                    "server": "Server version information",
                    "x-powered-by": "Technology stack information",
                    "x-aspnet-version": "ASP.NET version information",
                    "x-aspnetmvc-version": "ASP.NET MVC version information"
                }

                for header, description in sensitive_headers.items():
                    if header in headers:
                        findings.append({
                            "type": "information_disclosure",
                            "severity": Severity.MEDIUM,
                            "title": "Information Disclosure",
                            "description": f"Server is revealing {description} in response headers.",
                            "evidence": {
                                "header": header,
                                "value": headers[header]
                            },
                            "owasp_category": OwaspCategory.INSECURE_DESIGN,
                            "recommendation": "Remove or mask sensitive information from response headers. Configure the server to not expose version information or technology stack details.",
                            "affected_url": target_url
                        })

            except httpx.RequestError as e:
                logger.error(f"Error during sensitive data exposure scan", extra={"error": str(e)})
            except Exception as e:
                logger.error(f"An unexpected error occurred during sensitive data exposure scan", extra={"error": str(e)})

        logger.info(f"Finished Sensitive Data Exposure scan for {target_url}.")
        return findings

    def _mask_sensitive_data(self, data: str, pattern_type: str) -> str:
        """
        Mask sensitive data while preserving format.

        Args:
            data: The sensitive data to mask
            pattern_type: The type of sensitive data

        Returns:
            Masked version of the sensitive data
        """
        if pattern_type == "credit_card":
            return f"{data[:4]}{'*' * (len(data)-8)}{data[-4:]}"
        elif pattern_type == "email":
            username, domain = data.split('@')
            return f"{username[0]}{'*' * (len(username)-2)}{username[-1]}@{domain}"
        elif pattern_type == "ssn":
            return f"***-**-{data[-4:]}"
        else:
            return f"{data[:4]}{'*' * (len(data)-8)}{data[-4:]}"

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Sensitive Data Exposure Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("sensitive_data_exposure", SensitiveDataExposureScanner) 
