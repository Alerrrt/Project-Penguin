from typing import List, Dict, Any
from datetime import datetime
import logging

import httpx
from backend.utils import get_http_client
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger

from .base_scanner import BaseScanner
from ..config_types.models import ScanInput, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class MisconfigurationScanner(BaseScanner):
    """
    A scanner module for detecting security misconfigurations.
    """

    metadata = {
        "name": "Security Misconfiguration Scanner",
        "description": "Detects common security misconfigurations in web applications.",
        "owasp_category": "A05:2021 - Security Misconfiguration",
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
        Scans for security misconfigurations.
        """
        findings: List[Dict] = []
        target_url = target
        logger.info("Starting misconfiguration scan", extra={"target": target_url})

        try:
            async with get_http_client(timeout=30) as client:
                response = await client.get(target_url)
                
                # Check for server information disclosure
                if 'server' in response.headers:
                    logger.info("Server header reveals technology information", extra={
                        "server_header": response.headers['server'],
                        "target": target_url
                    })
                    findings.append({
                        "type": "server_information_disclosure",
                        "severity": Severity.MEDIUM,
                        "title": "Server Information Disclosure",
                        "description": f"Server header reveals technology information: {response.headers['server']}",
                        "evidence": {
                            "server_header": response.headers['server']
                        },
                        "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                        "recommendation": "Configure server to not reveal version information.",
                        "affected_url": target_url
                    })
                # Add more misconfiguration checks here...

        except httpx.HTTPStatusError as e:
            logger.warning("HTTP error while scanning", extra={
                "target": target_url,
                "error": str(e)
            })
        except httpx.RequestError as e:
            logger.warning("Request error while scanning", extra={
                "target": target_url,
                "error": str(e)
            })
        except Exception as e:
            logger.error("Unexpected error during misconfiguration scan", extra={
                "target": target_url,
                "error": str(e)
            }, exc_info=True)

        logger.info("Finished scanning for misconfigurations", extra={
            "target": target_url,
            "findings_count": len(findings)
        })
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Misconfiguration Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }
