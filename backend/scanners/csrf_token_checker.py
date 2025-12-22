import asyncio
from typing import List, Dict, Any
from datetime import datetime
from backend.utils import get_http_client
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.config_types.models import ScanInput, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class CsrfTokenCheckerScanner(BaseScanner):
    """
    A scanner module for checking CSRF tokens in HTML forms.
    """

    metadata = {
        "name": "CSRF Token Checker",
        "description": "Checks for the presence of anti-CSRF tokens in HTML forms.",
        "owasp_category": "A04:2021 - Insecure Design",
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
        Asynchronously crawls the target, identifies HTML forms, and checks for CSRF tokens.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for missing or improperly handled CSRF tokens.
        """
        findings: List[Dict] = []
        target_url = target
        logger.info(f"Starting CSRF Token Check for {target_url}")

        async with get_http_client(follow_redirects=True, timeout=30) as client:
            try:
                response = await client.get(target_url)
                response.raise_for_status()
                html_content = response.text
                soup = BeautifulSoup(html_content, 'html.parser')
                forms = soup.find_all('form')

                if not forms:
                    logger.info("No forms found on target", extra={
                        "target": target_url
                    })
                    return findings

                for form in forms:
                    form_action = form.get('action', '')
                    full_action_url = urljoin(target_url, form_action)
                    
                    # Check for hidden input fields that might be CSRF tokens
                    csrf_token_found = False
                    for input_tag in form.find_all('input', type='hidden'):
                        if "csrf" in input_tag.get('name', '').lower() or \
                           "token" in input_tag.get('name', '').lower():
                            csrf_token_found = True
                            break
                    
                    if not csrf_token_found:
                        findings.append({
                            "type": "missing_csrf_token",
                            "severity": Severity.HIGH,
                            "title": "Missing CSRF Token",
                            "description": f"Form at '{full_action_url}' does not appear to have a CSRF token. This may make it vulnerable to Cross-Site Request Forgery (CSRF) attacks.",
                            "evidence": {
                                "form_action": full_action_url,
                                "details": "No hidden input field resembling a CSRF token found."
                            },
                            "owasp_category": OwaspCategory.INSECURE_DESIGN,
                            "recommendation": "Implement anti-CSRF tokens for all state-changing operations via forms. Ensure tokens are unique per session/request and validated on the server-side.",
                            "affected_url": full_action_url
                        })

                    # TODO: For more advanced checks, we would need to:
                    # 1. Fetch the page twice in the same session to see if the token changes.
                    # 2. Attempt to submit the form without the token or with an invalid token.
                    # 3. Analyze server response to confirm token validation.

            except Exception as e:
                logger.error(f"Error fetching target for CSRF token check", extra={
                    "target": target_url,
                    "error": str(e)
                })
            except Exception as e:
                logger.error(f"Unexpected error during CSRF Token Check", extra={
                    "target": target_url,
                    "error": str(e)
                }, exc_info=True)

        logger.info(f"Completed CSRF Token Check for {target_url}. Found {len(findings)} issues.")
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "CSRF Token Checker Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("csrf_token_checker", CsrfTokenCheckerScanner) 
