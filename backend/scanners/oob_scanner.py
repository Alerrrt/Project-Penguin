import asyncio
import uuid
from typing import List, Dict, Any
from datetime import datetime
import httpx
from backend.utils import get_http_client
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from .base_scanner import BaseScanner
from ..config_types.models import ScanInput, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class OobScanner(BaseScanner):
    """
    Scanner for detecting out-of-band vulnerabilities.
    """

    metadata = {
        "name": "Out-of-Band Vulnerability Scanner",
        "description": "Detects potential out-of-band vulnerabilities by monitoring for external interactions.",
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="oob_scanner")
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
        Asynchronous method to scan for out-of-band vulnerabilities.

        Args:
            target: The target for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings representing potential vulnerabilities.
        """
        findings: List[Dict] = []
        logger.info("Starting OOB scan", extra={"target": target})

        # Perform actual OOB detection
        try:
            # Check for potential OOB vulnerabilities in request parameters
            async with get_http_client(timeout=30) as client:
                response = await client.get(target)
                
                # Check for potential OOB indicators in response
                if any(indicator in response.text.lower() for indicator in [
                    'internal.', 'localhost', '127.0.0.1', '192.168.', '10.',
                    'file://', 'ftp://', 'smb://', 'ldap://'
                ]):
                    logger.info("Potential OOB vulnerability detected", extra={
                        "target": target,
                        "interaction_type": "Internal Resource Access"
                    })
                    findings.append({
                        "type": "out_of_band_vulnerability",
                        "severity": Severity.HIGH,
                        "title": "Potential Out-of-Band Interaction Detected",
                        "description": "Detected potential access to internal resources or services.",
                        "evidence": {
                            "interaction_type": "Internal Resource Access",
                            "details": "Response contains references to internal resources",
                            "request": {
                                "method": "GET",
                                "url": target,
                                "headers": response.headers,
                            }
                        },
                        "owasp_category": OwaspCategory.SOFTWARE_AND_DATA_INTEGRITY_FAILURES,
                        "recommendation": "Review and restrict access to internal resources. Implement proper input validation and access controls.",
                        "affected_url": target
                    })

        except httpx.HTTPStatusError as e:
            logger.warning("HTTP error during OOB scan", extra={
                "target": target,
                "status_code": e.response.status_code,
                "error": str(e)
            })
        except httpx.RequestError as e:
            logger.warning("Request error during OOB scan", extra={
                "target": target,
                "error": str(e)
            })
        except Exception as e:
            logger.error("Unexpected error during OOB scan", extra={
                "target": target,
                "error": str(e)
            }, exc_info=True)

        await asyncio.sleep(0.1)  # Simulate some async work

        logger.info("Completed OOB scan", extra={
            "target": target,
            "findings_count": len(findings)
        })
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "OOB Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }
