import asyncio
import json
import pickle
import base64
from typing import List, Dict, Any
from datetime import datetime
from backend.utils import get_http_client
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.config_types.models import ScanInput, Severity, OwaspCategory

logger = get_context_logger(__name__)

class InsecureDeserializationScanner(BaseScanner):
    """
    A scanner module for detecting insecure deserialization vulnerabilities.
    """

    metadata = {
        "name": "Insecure Deserialization",
        "description": "Detects insecure deserialization vulnerabilities by sending crafted payloads in various formats.",
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="insecure_deserialization_scanner")
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
            results = await self._perform_scan(scan_input.target, scan_input.options)
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
        Asynchronously checks for insecure deserialization vulnerabilities by sending crafted payloads.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for detected insecure deserialization vulnerabilities.
        """
        findings: List[Dict] = []
        target_url = target
        logger.info(f"Starting Insecure Deserialization scan for {target_url}")

        # Test payloads for different deserialization formats
        test_payloads = [
            # JSON payload with prototype pollution
            {
                "json": json.dumps({
                    "__proto__": {
                        "isAdmin": True
                    }
                })
            },
            # Python pickle payload
            {
                "pickle": base64.b64encode(pickle.dumps({"command": "ls"})).decode()
            },
            # PHP serialized object
            {
                "php": "O:8:\"stdClass\":1:{s:1:\"x\";s:4:\"test\";}"
            }
        ]

        async with get_http_client(follow_redirects=True, timeout=30) as client:
            for payload in test_payloads:
                try:
                    # Try different content types
                    content_types = [
                        "application/json",
                        "application/x-python-serialize",
                        "application/x-php-serialized"
                    ]

                    for content_type in content_types:
                        headers = {
                            "Content-Type": content_type
                        }
                        
                        # Send the appropriate payload based on content type
                        if content_type == "application/json":
                            data = payload.get("json")
                            if not data:
                                continue
                        elif content_type == "application/x-python-serialize":
                            data = payload.get("pickle")
                            if not data:
                                continue
                        else:
                            data = payload.get("php")
                            if not data:
                                continue

                        response = await client.post(target_url, content=data, headers=headers)
                        
                        # Check for indicators of successful deserialization
                        if response.status_code != 400 and response.status_code != 500:
                            findings.append({
                                "type": "insecure_deserialization",
                                "severity": Severity.HIGH,
                                "title": "Insecure Deserialization",
                                "description": "Potential insecure deserialization vulnerability detected. The application appears to be processing serialized data without proper validation.",
                                "evidence": {
                                    "content_type": content_type,
                                    "payload": data,
                                    "response_status": response.status_code,
                                    "response_length": len(response.text)
                                },
                                "owasp_category": OwaspCategory.SOFTWARE_AND_DATA_INTEGRITY_FAILURES,
                                "recommendation": "Implement strict input validation for all deserialized data. Use safe deserialization methods and avoid using native deserialization functions when possible. Consider using a whitelist of allowed classes/types.",
                                "affected_url": target_url
                            })

                except Exception as e:
                    logger.error(f"Error testing deserialization", extra={
                        "target": target_url,
                        "content_type": content_type,
                        "error": str(e)
                    })
                except Exception as e:
                    logger.error(f"Unexpected error during deserialization scan", extra={
                        "target": target_url,
                        "content_type": content_type,
                        "error": str(e)
                    }, exc_info=True)

        logger.info(f"Completed Insecure Deserialization scan for {target_url}. Found {len(findings)} issues.")
        return findings


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("insecure_deserialization", InsecureDeserializationScanner) 
