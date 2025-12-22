# -*- coding: utf-8 -*-
import asyncio
from typing import List, Dict, Any
from backend.utils import get_http_client
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger

from .base_scanner import BaseScanner
from ..config_types.models import ScanInput, Severity, OwaspCategory

logger = get_context_logger(__name__)

class ClickjackingScreenshotterScanner(BaseScanner):
    """
    A scanner module for detecting Clickjacking vulnerabilities.
    """

    metadata = {
        "name": "Clickjacking Screenshotter",
        "description": "Detects Clickjacking vulnerabilities by checking X-Frame-Options and CSP headers.",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="clickjacking_screenshotter")
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
        Asynchronously attempts to detect clickjacking by simulating iframe embedding.
        """
        findings: List[Dict] = []
        target_url = target
        logger.info("Starting Clickjacking Screenshotter scan", extra={
            "target": target_url,
            "scanner": self.__class__.__name__
        })

        try:
            async with get_http_client(follow_redirects=True, timeout=30) as client:
                response = await client.get(target_url)
                response.raise_for_status()

                headers = response.headers
                x_frame_options = headers.get("X-Frame-Options")
                csp = headers.get("Content-Security-Policy")
                csp_report_only = headers.get("Content-Security-Policy-Report-Only")

                # Check for X-Frame-Options header
                if x_frame_options and x_frame_options.lower() in ["deny", "sameorigin"]:
                    logger.info("X-Frame-Options present and set to protection value", extra={
                        "header": x_frame_options,
                        "target": target_url,
                        "scanner": self.__class__.__name__
                    })
                else:
                    logger.info("Potential clickjacking vulnerability detected - X-Frame-Options", extra={
                        "header": x_frame_options or "Missing",
                        "target": target_url,
                        "scanner": self.__class__.__name__
                    })
                    findings.append({
                        "type": "potential_clickjacking",
                        "severity": Severity.MEDIUM,
                        "title": "Potential Clickjacking Vulnerability - X-Frame-Options",
                        "description": "The page might be vulnerable to Clickjacking. X-Frame-Options header is either missing or not set to 'DENY'/'SAMEORIGIN'.",
                        "evidence": {
                            "url": target_url,
                            "x_frame_options_header": x_frame_options or "Missing",
                            "csp_header": csp or "Missing",
                            "csp_report_only_header": csp_report_only or "Missing",
                            "details": "The page could potentially be framed by an attacker due to missing or weak X-Frame-Options header."
                        },
                        "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                        "recommendation": "Implement the X-Frame-Options header with 'DENY' or 'SAMEORIGIN'. Additionally, consider implementing Content-Security-Policy with frame-ancestors directive for better protection.",
                        "affected_url": target_url
                    })

                # Check for CSP frame-ancestors directive
                if csp and "frame-ancestors" in csp.lower():
                    logger.info("CSP frame-ancestors directive present", extra={
                        "csp": csp,
                        "target": target_url,
                        "scanner": self.__class__.__name__
                    })
                else:
                    logger.info("Potential clickjacking vulnerability detected - CSP", extra={
                        "csp": csp or "Missing",
                        "target": target_url,
                        "scanner": self.__class__.__name__
                    })
                    findings.append({
                        "type": "potential_clickjacking",
                        "severity": Severity.MEDIUM,
                        "title": "Potential Clickjacking Vulnerability - CSP",
                        "description": "The page might be vulnerable to Clickjacking. Content-Security-Policy header is either missing or does not include frame-ancestors directive.",
                        "evidence": {
                            "url": target_url,
                            "x_frame_options_header": x_frame_options or "Missing",
                            "csp_header": csp or "Missing",
                            "csp_report_only_header": csp_report_only or "Missing",
                            "details": "The page could potentially be framed by an attacker due to missing or weak Content-Security-Policy frame-ancestors directive."
                        },
                        "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                        "recommendation": "Implement Content-Security-Policy with frame-ancestors directive. For maximum security, use 'frame-ancestors \'none\'' to prevent all framing, or 'frame-ancestors \'self\'' to allow only same-origin framing.",
                        "affected_url": target_url
                    })

        except Exception as e:
            logger.warning("Request error during clickjacking check", extra={
                "url": target_url,
                "error": str(e),
                "scanner": self.__class__.__name__
            })
        except Exception as e:
            logger.error("Unexpected error during clickjacking check", extra={
                "url": target_url,
                "error": str(e),
                "scanner": self.__class__.__name__
            }, exc_info=True)

        logger.info("Finished Clickjacking Screenshotter scan", extra={
            "target": target_url,
            "findings_count": len(findings),
            "scanner": self.__class__.__name__
        })
        return findings 
