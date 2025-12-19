# -*- coding: utf-8 -*-
import asyncio
from datetime import datetime
from typing import List, Dict
import httpx
import re
from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.config_types.models import ScanInput, Severity, OwaspCategory
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils import get_http_client
from backend.utils.crawler import seed_urls
from backend.utils.logging_config import get_context_logger
import logging

logger = get_context_logger(__name__)

class XssScanner(BaseScanner):
    """
    A scanner module for detecting Cross-Site Scripting (XSS) vulnerabilities.
    """

    metadata = {
        "name": "XSS Scanner",
        "description": "Detects Cross-Site Scripting (XSS) vulnerabilities.",
        "owasp_category": OwaspCategory.A03_XSS,
        "author": "Project Nightingale Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="xss_scanner")
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        """
        This is the entry point for the scanner. It will delegate to the
        private _perform_scan method. The boilerplate for logging, metrics,
        and broadcasting is handled by higher-level components.
        """
        try:
            return await self._perform_scan(scan_input.target, scan_input.options or {})
        except Exception as e:
            logger.error(f"XSS scan failed: {e}", exc_info=True)
            return [self._create_error_finding(f"XSS scan failed: {e}")]

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Perform the actual XSS vulnerability scan concurrently.
        """
        findings: List[Dict] = []
        logger.info("Starting concurrent XSS scan", extra={"target": target})

        # Safer, varied payload set including common contexts
        test_payloads = options.get('payloads', [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "\"><svg/onload=alert(1)>",
            "'\"><svg/onload=alert(1)>",
            "</script><script>alert(1)</script>",
            "<img src=1 onerror=alert(1)>",
            "<a href=javascript:alert(1)>click</a>",
        ])

        test_params = options.get('parameters', [
            'q', 'search', 'id', 'input', 'query', 'keyword',
            'name', 'user', 'username', 'email', 'message',
            'comment', 'content', 'text', 'data'
        ])

        try:
            timeout = float(options.get('timeout', 10.0))
            use_seeds = bool(options.get('use_seeds', True))
            max_urls = int(options.get('max_urls', 6))
            
            # Concurrency control within the scanner
            concurrency_limit = int(options.get('concurrency', 10))
            semaphore = asyncio.Semaphore(concurrency_limit) # Process 10 concurrent requests at a time

            async with get_http_client(verify=False, follow_redirects=True, timeout=timeout) as client:
                urls_to_test: List[str] = [target]
                if use_seeds:
                    try:
                        urls_to_test.extend(await seed_urls(target, max_urls=max_urls))
                    except Exception:
                        pass
                
                # Deduplicate URLs
                urls_to_test = list(set(urls_to_test))
                
                tasks = []

                # Helper to perform a single test request with semaphore
                async def test_request(method: str, url: str, data: Dict[str, str] = None, payload: str = ""):
                    async with semaphore:
                        try:
                            if method == 'GET':
                                response = await client.get(url)
                            else:
                                response = await client.post(url, data=data)
                            
                            body = response.text
                            # Reflection heuristic
                            if (payload in body) or (payload.replace('<','&lt;').replace('>','&gt;') in body):
                                logger.info("Potential XSS vulnerability detected", extra={"url": url, "payload": payload})
                                return {
                                    "type": "reflected_xss",
                                    "severity": Severity.HIGH,
                                    "title": "Reflected XSS Vulnerability",
                                    "description": f"Found reflected XSS vulnerability in {method} request to {url}",
                                    "evidence": {
                                        "url": url,
                                        "method": method,
                                        "payload": payload,
                                        "reflection": body[:200]
                                    },
                                    "owasp_category": OwaspCategory.INJECTION,
                                    "remediation": "Implement contextual output encoding, validate and sanitize inputs, avoid dangerous sinks."
                                }
                        except Exception as e:
                            # Log only at debug to reduce noise for expected failures (timeouts/connection errors)
                            logger.debug("Error testing XSS payload", extra={"url": url, "error": str(e)})
                        return None

                # 1. Analyze pages for Forms
                for page in urls_to_test:
                    try:
                        response = await client.get(page)
                        content = response.text
                        forms = re.findall(r'<form[^>]*>.*?</form>', content, re.DOTALL | re.IGNORECASE)
                        
                        for form in forms:
                            form_action_match = re.search(r'action=["\']([^"\']*)["\']', form)
                            form_method_match = re.search(r'method=["\']([^"\']*)["\']', form)

                            if form_action_match:
                                form_url = form_action_match.group(1)
                                if not form_url.startswith(('http://', 'https://')):
                                    form_url = f"{page.rstrip('/')}/{form_url.lstrip('/')}"
                                
                                method = form_method_match.group(1).upper() if form_method_match else 'POST'
                                
                                for payload in test_payloads:
                                    if method == 'GET':
                                        # Assuming the first test_param is the most likely for GET forms
                                        test_url = f"{form_url}?{test_params[0]}={payload}"
                                        tasks.append(test_request('GET', test_url, payload=payload))
                                    else:
                                        data = {param: payload for param in test_params}
                                        tasks.append(test_request('POST', form_url, data=data, payload=payload))
                    except Exception:
                        continue

                # 2. URL Parameter Probes (GET)
                for page in urls_to_test:
                    for param in test_params:
                        for payload in test_payloads:
                             # Construct URL properly
                            separator = '&' if '?' in page else '?'
                            test_url = f"{page}{separator}{param}={payload}"
                            tasks.append(test_request('GET', test_url, payload=payload))

                if tasks:
                    logger.info(f"Executing {len(tasks)} XSS tests concurrently...")
                    results = await asyncio.gather(*tasks)
                    # Filter out None results
                    for res in results:
                        if res:
                            findings.append(res)

        except Exception as e:
            logger.error("Unexpected error during XSS scan", extra={
                "target": target,
                "error": str(e)
            }, exc_info=True)

        logger.info("Finished XSS scan", extra={
            "target": target,
            "findings_count": len(findings)
        })
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "XSS Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }
