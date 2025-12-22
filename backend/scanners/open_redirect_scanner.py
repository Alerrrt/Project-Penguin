# -*- coding: utf-8 -*-
import re
from typing import List, Dict, Any
from datetime import datetime
import httpx
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.config_types.models import ScanInput, Severity, OwaspCategory
from backend.utils import get_http_client
from backend.utils.crawler import seed_urls
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

logger = logging.getLogger(__name__)

class OpenRedirectScanner(BaseScanner):
    """
    Scanner for detecting open redirect vulnerabilities.
    """
    metadata = {
        "name": "Open Redirect",
        "description": "Detects open redirect vulnerabilities by injecting common payloads into redirect parameters and analyzing responses.",
        "owasp_category": "A10:2021 - Server-Side Request Forgery (SSRF)",
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
        findings: List[Dict] = []
        logger.info("Starting open redirect scan", extra={
            "target": target,
            "scanner": self.__class__.__name__
        })
        
        # Common redirect parameters and payloads
        redirect_params = options.get('parameters', [
            'next', 'url', 'target', 'rurl', 'dest', 'destination', 'redir', 'redirect', 'redirect_url', 'redirect_uri', 'continue', 'return', 'returnTo', 'return_to'
        ])
        test_host = options.get('test_host', 'evil.example')
        payloads = options.get('payloads', [
            f'https://{test_host}',
            f'//{test_host}',
            f'/\\{test_host}',
            f'///{test_host}',
            f'http://{test_host}',
            f'{test_host}',
            f'////{test_host}',
            f'\\{test_host}',
        ])
        timeout = float(options.get('timeout', 15))
        max_urls = int(options.get('max_urls', 8))
        use_seeds = bool(options.get('use_seeds', True))
        
        # Build list of URLs to test (base + optional seeds)
        urls_to_test: List[str] = [target]
        if use_seeds:
            try:
                seeds = await seed_urls(target, max_urls=max_urls)
                urls_to_test = list(dict.fromkeys(urls_to_test + seeds))
            except Exception:
                pass

        target_origin = urlparse(target)

        def is_external(location_value: str) -> bool:
            try:
                loc = urlparse(location_value)
                return bool(loc.netloc) and loc.netloc != target_origin.netloc
            except Exception:
                return False

        try:
            async with get_http_client(timeout=timeout, follow_redirects=False) as client:
                for base_url in urls_to_test:
                    parsed = urlparse(base_url)
                    base_qs = parse_qs(parsed.query)
                    for param in redirect_params:
                        for payload in payloads:
                            try:
                                new_qs = base_qs.copy()
                                new_qs[param] = [payload]
                                test_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
                                response = await client.get(test_url)
                                location = response.headers.get('location', '')

                                # 3xx redirect to external host or our test host
                                if response.status_code in (301, 302, 303, 307, 308) and (test_host in location or is_external(location)):
                                    findings.append({
                                        "type": "open_redirect",
                                        "severity": Severity.MEDIUM,
                                        "title": "Open Redirect Vulnerability",
                                        "description": f"Potential open redirect via parameter '{param}' with payload '{payload}'.",
                                        "evidence": {
                                            "url": test_url,
                                            "parameter": param,
                                            "payload": payload,
                                            "location": location,
                                            "status_code": response.status_code
                                        },
                                        "owasp_category": OwaspCategory.SSRF,
                                        "recommendation": "Validate and whitelist redirect destinations. Only allow relative paths or a strict allowlist of hosts."
                                    })

                                # Heuristic: 200 with meta refresh or JS redirect containing our payload host
                                ct = response.headers.get('content-type', '').lower()
                                if (response.status_code == 200 and 'text/html' in ct):
                                    body_lower = response.text.lower()[:4000]
                                    if (f'meta http-equiv="refresh"' in body_lower and test_host in body_lower) or ('window.location' in body_lower and test_host in body_lower):
                                        findings.append({
                                            "type": "open_redirect",
                                            "severity": Severity.LOW,
                                            "title": "Client-side Redirect Detected",
                                            "description": f"Page contains a client-side redirect referencing '{test_host}'.",
                                            "evidence": {"url": test_url},
                                            "owasp_category": OwaspCategory.SSRF,
                                            "recommendation": "Avoid client-side redirects to untrusted domains. Sanitize and validate destinations."
                                        })
                            except Exception as e:
                                logger.warning("Error testing open redirect payload", extra={
                                    "url": base_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "error": str(e),
                                    "scanner": self.__class__.__name__
                                })
                                continue
        except Exception as e:
            logger.error("Unexpected error during open redirect scan", extra={
                "target": target,
                "error": str(e),
                "scanner": self.__class__.__name__
            }, exc_info=True)

        logger.info("Finished open redirect scan", extra={
            "target": target,
            "findings_count": len(findings),
            "scanner": self.__class__.__name__
        })
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Open Redirect Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }

def register(scanner_registry: ScannerRegistry) -> None:
    scanner_registry.register("open_redirect", OpenRedirectScanner) 
