import asyncio
import httpx
from typing import List, Dict, Any
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from .base_scanner import BaseScanner
from ..config_types.models import ScanInput, Severity, OwaspCategory
from backend.utils import get_http_client

logger = logging.getLogger(__name__)

class SecurityHeadersAnalyzer(BaseScanner):
    """
    A scanner module for analyzing security headers in HTTP responses.
    """

    metadata = {
        "name": "Security Headers Analyzer",
        "description": "Analyzes security headers in HTTP responses to identify missing or misconfigured headers.",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    # Define required security headers and their recommended values (expanded)
    REQUIRED_HEADERS = {
        "Strict-Transport-Security": {
            "recommended": "max-age=31536000; includeSubDomains; preload",
            "description": "Enforces HTTPS connections",
            "severity": Severity.HIGH
        },
        "X-Content-Type-Options": {
            "recommended": "nosniff",
            "description": "Prevents MIME type sniffing",
            "severity": Severity.MEDIUM
        },
        "X-Frame-Options": {
            "recommended": "DENY",
            "description": "Prevents clickjacking attacks",
            "severity": Severity.MEDIUM
        },
        # Historical header; prefer CSP. Keep as informational if present and weak.
        "X-XSS-Protection": {
            "recommended": "1; mode=block",
            "description": "Legacy header; prefer CSP instead. Some browsers ignore this.",
            "severity": Severity.LOW
        },
        "Content-Security-Policy": {
            "recommended": "default-src 'self'",
            "description": "Controls resource loading",
            "severity": Severity.HIGH
        },
        "Referrer-Policy": {
            "recommended": "strict-origin-when-cross-origin",
            "description": "Controls referrer information",
            "severity": Severity.LOW
        },
        "Permissions-Policy": {
            "recommended": "geolocation=(), microphone=(), camera=()",
            "description": "Controls browser features",
            "severity": Severity.MEDIUM
        },
        # Modern isolation headers
        "Cross-Origin-Opener-Policy": {
            "recommended": "same-origin",
            "description": "Helps isolate browsing context (COOP)",
            "severity": Severity.MEDIUM
        },
        "Cross-Origin-Embedder-Policy": {
            "recommended": "require-corp",
            "description": "Requires cross-origin resources to grant permission (COEP)",
            "severity": Severity.MEDIUM
        },
        "Cross-Origin-Resource-Policy": {
            "recommended": "same-origin",
            "description": "Controls cross-origin resource sharing (CORP)",
            "severity": Severity.LOW
        },
        "X-Permitted-Cross-Domain-Policies": {
            "recommended": "none",
            "description": "Prevents Adobe cross-domain policy abuse",
            "severity": Severity.LOW
        }
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="security_headers_analyzer")
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
        Analyzes security headers in the HTTP response.

        Args:
            target: The target URL to scan
            options: Additional scan options

        Returns:
            List of findings related to missing or misconfigured security headers
        """
        findings: List[Dict] = []
        logger.info("Starting security headers analysis", extra={"target": target})

        try:
            timeout = float(options.get("timeout", 30))
            async with get_http_client(timeout=timeout) as client:
                response = await client.get(target)
                headers = response.headers

                # Check each required header
                for header, config in self.REQUIRED_HEADERS.items():
                    if header not in headers:
                        findings.append({
                            "type": "missing_security_header",
                            "severity": config["severity"],
                            "title": f"Missing {header} Header",
                            "description": f"The {header} header is missing. {config['description']}",
                            "evidence": {
                                "header": header,
                                "recommended_value": config["recommended"],
                                "current_value": None
                            },
                            "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                            "recommendation": f"Add the {header} header with value: {config['recommended']}",
                            "affected_url": target
                        })
                        logger.info("Missing header", extra={"header": header})
                    else:
                        current_value = headers[header]
                        # CSP is complex; treat as misconfigured if obviously weak
                        weak = False
                        if header.lower() == "content-security-policy":
                            weak = any(k in current_value.lower() for k in ["unsafe-inline", "unsafe-eval"]) or "default-src" not in current_value.lower()
                        if weak or current_value.lower() != config["recommended"].lower():
                            findings.append({
                                "type": "misconfigured_security_header",
                                "severity": config["severity"],
                                "title": f"Misconfigured {header} Header",
                                "description": f"The {header} header is present but may not be optimally configured. {config['description']}",
                                "evidence": {
                                    "header": header,
                                    "recommended_value": config["recommended"],
                                    "current_value": current_value
                                },
                                "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                                "recommendation": f"Update the {header} header to: {config['recommended']}",
                                "affected_url": target
                            })
                            logger.info("Misconfigured header", extra={"header": header})

                # CORS high-level quick checks to reduce duplicate network calls
                acao = headers.get("Access-Control-Allow-Origin")
                acac = headers.get("Access-Control-Allow-Credentials", "").lower()
                if acao == "*" and acac == "true":
                    findings.append({
                        "type": "cors",
                        "severity": Severity.HIGH,
                        "title": "CORS allows any origin with credentials",
                        "description": "Access-Control-Allow-Origin is '*' while credentials are allowed.",
                        "evidence": {"headers": dict(headers)},
                        "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                        "recommendation": "Avoid '*' with credentials; return a specific trusted origin.",
                        "affected_url": target
                    })

        except httpx.RequestError as e:
            logger.error("Failed to connect to target", extra={
                "target": target,
                "error": str(e)
            })
            findings.append({
                "type": "connection_error",
                "severity": Severity.HIGH,
                "title": "Connection Error",
                "description": f"Failed to connect to {target}",
                "evidence": {"error": str(e)},
                "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                "recommendation": "Ensure the target is accessible and try again",
                "affected_url": target
            })
        except Exception as e:
            logger.error("Unexpected error during security headers analysis", extra={
                "target": target,
                "error": str(e)
            }, exc_info=True)
            findings.append({
                "type": "unexpected_error",
                "severity": Severity.HIGH,
                "title": "Unexpected Error",
                "description": "An unexpected error occurred during the scan",
                "evidence": {"error": str(e)},
                "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                "recommendation": "Check the scanner logs for more details",
                "affected_url": target
            })

        logger.info("Completed security headers analysis", extra={
            "target": target,
            "findings_count": len(findings)
        })
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Security Headers Analyzer Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
