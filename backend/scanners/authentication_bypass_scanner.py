from datetime import datetime
from typing import List, Dict, Any
from backend.utils import get_http_client
import re
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity, OwaspCategory
import logging

logger = logging.getLogger(__name__)

class AuthenticationBypassScanner(BaseScanner):
    """
    A scanner module for detecting authentication bypass vulnerabilities.
    """

    metadata = {
        "name": "Authentication Bypass",
        "description": "Detects authentication bypass vulnerabilities by testing various bypass techniques.",
        "owasp_category": "A02:2021 - Cryptographic Failures",
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
        Perform the actual authentication bypass vulnerability scan.
        
        Args:
            target: Target URL to scan
            options: Scan options including timeout and test payloads
            
        Returns:
            List of findings containing authentication bypass vulnerabilities
        """
        findings = []
        timeout = options.get('timeout', 10)
        
        # Common protected endpoints
        protected_endpoints = options.get('protected_endpoints', [
            '/admin',
            '/dashboard',
            '/profile',
            '/settings',
            '/api/admin',
            '/api/user',
            '/api/settings',
            '/api/profile'
        ])
        
        # Common bypass techniques
        bypass_techniques = [
            # Header manipulation
            {
                'headers': {
                    'X-Original-URL': '/admin',
                    'X-Rewrite-URL': '/admin',
                    'X-Forwarded-For': '127.0.0.1',
                    'X-Forwarded-Host': 'localhost',
                    'X-Forwarded-Proto': 'https',
                    'X-Custom-IP-Authorization': '127.0.0.1'
                }
            },
            # Parameter manipulation
            {
                'params': {
                    'admin': 'true',
                    'isAdmin': 'true',
                    'role': 'admin',
                    'user': 'admin',
                    'type': 'admin',
                    'access': 'admin',
                    'auth': 'true',
                    'authorized': 'true'
                }
            },
            # Cookie manipulation
            {
                'cookies': {
                    'admin': 'true',
                    'isAdmin': 'true',
                    'role': 'admin',
                    'user': 'admin',
                    'type': 'admin',
                    'access': 'admin',
                    'auth': 'true',
                    'authorized': 'true'
                }
            },
            # JWT manipulation
            {
                'headers': {
                    'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.'
                }
            }
        ]
        
        async with get_http_client(timeout=timeout) as client:
            try:
                # Test each protected endpoint
                for endpoint in protected_endpoints:
                    url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
                    
                    try:
                        # First, check if endpoint exists and requires authentication
                        response = await client.get(url)
                        
                        if response.status_code in [401, 403]:
                            # Endpoint requires authentication, test bypass techniques
                            for technique in bypass_techniques:
                                try:
                                    # Apply bypass technique
                                    if 'headers' in technique:
                                        bypass_response = await client.get(url, headers=technique['headers'])
                                    elif 'params' in technique:
                                        bypass_response = await client.get(url, params=technique['params'])
                                    elif 'cookies' in technique:
                                        bypass_response = await client.get(url, cookies=technique['cookies'])
                                    else:
                                        continue
                                    
                                    # Check if bypass was successful
                                    if bypass_response.status_code == 200:
                                        findings.append({
                                            "type": "authentication_bypass",
                                            "severity": Severity.CRITICAL,
                                            "title": "Authentication Bypass Vulnerability",
                                            "description": f"Successfully bypassed authentication using {list(technique.keys())[0]} manipulation.",
                                            "evidence": {
                                                "url": url,
                                                "technique": list(technique.keys())[0],
                                                "payload": technique[list(technique.keys())[0]],
                                                "status_code": bypass_response.status_code,
                                                "response_length": len(bypass_response.text)
                                            },
                                            "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                            "recommendation": "Implement proper authentication checks. Validate all user input and enforce strict access controls. Use secure session management and token validation."
                                        })
                                    
                                except Exception as e:
                                    logger.warning(
                                        f"Error testing bypass technique for {url}",
                                        extra={
                                            "url": url,
                                            "technique": list(technique.keys())[0],
                                            "error": str(e)
                                        }
                                    )
                                    continue
                            
                    except Exception as e:
                        logger.warning(
                            f"Error checking endpoint {url}",
                            extra={
                                "url": url,
                                "error": str(e)
                            }
                        )
                        continue
                
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
        return { "type": "error", "severity": Severity.INFO, "title": "Authentication Bypass Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
