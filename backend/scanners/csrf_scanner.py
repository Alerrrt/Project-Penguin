from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from backend.scanners.base_scanner import BaseScanner
from typing import List, Dict
from backend.config_types.models import ScanInput, Severity, OwaspCategory
from backend.utils import get_http_client
import re
import logging

logger = logging.getLogger(__name__)

class CSRFScanner(BaseScanner):
    metadata = {
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "Detects CSRF vulnerabilities by analyzing forms and endpoints for missing CSRF protections.",
        "owasp_category": "A01:2021 - Broken Access Control",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        """
        Perform a security scan with circuit breaker protection.
        
        Args:
            scan_input: The input for the scan, including target and options.
            
        Returns:
            List of scan results
        """
        start_time = datetime.now()
        scan_id = f"{self.__class__.__name__}_{start_time.strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Log scan start
            logger.info(
                "Scan started",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "options": scan_input.options
                }
            )
            
            # Perform scan
            results = await self._perform_scan(scan_input.target, scan_input.options or {})
            
            # Update metrics
            self._update_metrics(True, start_time)
            
            # Log scan completion
            logger.info(
                "Scan completed",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "result_count": len(results)
                }
            )
            
            return results
            
        except Exception as e:
            # Update metrics
            self._update_metrics(False, start_time)
            
            # Log error
            logger.error(
                "Scan failed",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "error": str(e)
                },
                exc_info=True
            )
            raise

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Perform the actual CSRF vulnerability scan.
        
        Args:
            target: Target URL to scan
            options: Scan options including timeout
            
        Returns:
            List of findings containing CSRF vulnerabilities
        """
        findings = []
        timeout = options.get('timeout', 10)
        
        async with get_http_client(timeout=timeout) as client:
            try:
                # Get the page content
                response = await client.get(target)
                content = response.text
                
                # Look for forms
                forms = re.findall(r'<form[^>]*>.*?</form>', content, re.DOTALL)
                
                for form in forms:
                    # Check for CSRF token
                    has_csrf_token = bool(re.search(r'name=["\']csrf["\']|name=["\']_csrf["\']|name=["\']csrf_token["\']', form))
                    
                    # Check for SameSite cookie attribute
                    cookies = response.headers.get('set-cookie', '')
                    has_samesite = 'SameSite' in cookies
                    
                    # Check for custom headers
                    has_custom_header = bool(re.search(r'X-CSRF-Token|X-XSRF-Token|X-Requested-With', form))
                    
                    if not (has_csrf_token or has_samesite or has_custom_header):
                        findings.append({
                            "type": "csrf_vulnerability",
                            "severity": Severity.HIGH,
                            "title": "Missing CSRF Protection",
                            "description": "Form submission lacks CSRF protection mechanisms",
                            "evidence": {
                                "url": target,
                                "form_preview": form[:200],
                                "missing_protections": {
                                    "csrf_token": not has_csrf_token,
                                    "samesite_cookie": not has_samesite,
                                    "custom_header": not has_custom_header
                                }
                            },
                            "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                            "recommendation": "Implement CSRF protection using one or more of: CSRF tokens, SameSite cookies, or custom headers."
                        })
                
            except Exception as e:
                logger.warning(
                    f"Error scanning target {target}",
                    extra={
                        "target": target,
                        "error": str(e)
                    }
                )
                
        return findings 

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "CSRF Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
