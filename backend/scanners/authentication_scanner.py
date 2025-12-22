from datetime import datetime
from typing import List, Dict, Any
import re
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity, OwaspCategory
import logging
from backend.utils import get_http_client

logger = logging.getLogger(__name__)

class AuthenticationScanner(BaseScanner):
    """
    A scanner module for detecting authentication vulnerabilities.
    """

    metadata = {
        "name": "Authentication",
        "description": "Detects authentication vulnerabilities by analyzing login mechanisms and session management.",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "author": "Project Echo Team",
        "version": "2.0"
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
        Perform the actual authentication vulnerability scan.
        
        Args:
            target: Target URL to scan
            options: Scan options including timeout and test credentials
            
        Returns:
            List of findings containing authentication vulnerabilities
        """
        findings = []
        timeout = options.get('timeout', 10)
        
        # Common login endpoints
        login_endpoints = options.get('login_endpoints', [
            '/login',
            '/signin',
            '/auth',
            '/sign-in',
            '/log-in',
            '/account/login',
            '/user/login',
            '/admin/login'
        ])
        
        # Test credentials
        test_credentials = options.get('test_credentials', [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'test', 'password': 'test'},
            {'username': 'user', 'password': 'password'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'root', 'password': 'root'}
        ])
        
        # Common authentication headers
        auth_headers = [
            'Authorization',
            'X-Auth-Token',
            'X-API-Key',
            'X-Access-Token',
            'Cookie'
        ]
        
        # Common session cookie names
        session_cookies = [
            'session',
            'sessionid',
            'sessid',
            'PHPSESSID',
            'JSESSIONID',
            'ASP.NET_SessionId',
            'auth',
            'token'
        ]
        
        async with get_http_client(timeout=timeout) as client:
            try:
                # Check for login endpoints
                for endpoint in login_endpoints:
                    login_url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
                    
                    try:
                        # Check if endpoint exists
                        response = await client.get(login_url)
                        
                        if response.status_code != 404:
                            # Test for missing HTTPS
                            if not login_url.startswith('https://'):
                                findings.append({
                                    "type": "authentication_vulnerability",
                                    "severity": Severity.HIGH,
                                    "title": "Login Page Not Using HTTPS",
                                    "description": "Login page is accessible over HTTP instead of HTTPS.",
                                    "evidence": {
                                        "url": login_url,
                                        "protocol": "http"
                                    },
                                    "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                    "recommendation": "Enforce HTTPS for all authentication endpoints. Implement HSTS and redirect HTTP to HTTPS."
                                })
                            
                            # Test for weak password policy
                            for creds in test_credentials:
                                try:
                                    login_response = await client.post(
                                        login_url,
                                        json=creds,
                                        headers={'Content-Type': 'application/json'}
                                    )
                                    
                                    if login_response.status_code == 200:
                                        findings.append({
                                            "type": "authentication_vulnerability",
                                            "severity": Severity.HIGH,
                                            "title": "Weak Password Policy",
                                            "description": "Application accepts weak default credentials.",
                                            "evidence": {
                                                "url": login_url,
                                                "credentials": creds,
                                                "status_code": login_response.status_code
                                            },
                                            "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                            "recommendation": "Implement strong password policies. Enforce minimum length, complexity, and prevent use of common passwords."
                                        })
                                        break
                                        
                                except Exception as e:
                                    logger.warning(
                                        f"Error testing credentials for {login_url}",
                                        extra={
                                            "url": login_url,
                                            "error": str(e)
                                        }
                                    )
                                    continue
                            
                            # Check for session management
                            if 'Set-Cookie' in response.headers:
                                for cookie in session_cookies:
                                    if cookie.lower() in response.headers['Set-Cookie'].lower():
                                        # Check for secure flag
                                        if 'secure' not in response.headers['Set-Cookie'].lower():
                                            findings.append({
                                                "type": "authentication_vulnerability",
                                                "severity": Severity.MEDIUM,
                                                "title": "Missing Secure Flag on Session Cookie",
                                                "description": "Session cookie is not marked as secure.",
                                                "evidence": {
                                                    "url": login_url,
                                                    "cookie": response.headers['Set-Cookie']
                                                },
                                                "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                                "recommendation": "Set the Secure flag on all session cookies. This ensures cookies are only sent over HTTPS."
                                            })
                                        
                                        # Check for HttpOnly flag
                                        if 'httponly' not in response.headers['Set-Cookie'].lower():
                                            findings.append({
                                                "type": "authentication_vulnerability",
                                                "severity": Severity.MEDIUM,
                                                "title": "Missing HttpOnly Flag on Session Cookie",
                                                "description": "Session cookie is not marked as HttpOnly.",
                                                "evidence": {
                                                    "url": login_url,
                                                    "cookie": response.headers['Set-Cookie']
                                                },
                                                "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                                "recommendation": "Set the HttpOnly flag on all session cookies. This prevents JavaScript access to the cookie."
                                            })
                                        
                                        # Check for SameSite attribute
                                        if 'samesite' not in response.headers['Set-Cookie'].lower():
                                            findings.append({
                                                "type": "authentication_vulnerability",
                                                "severity": Severity.MEDIUM,
                                                "title": "Missing SameSite Attribute on Session Cookie",
                                                "description": "Session cookie does not have SameSite attribute set.",
                                                "evidence": {
                                                    "url": login_url,
                                                    "cookie": response.headers['Set-Cookie']
                                                },
                                                "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                                "recommendation": "Set the SameSite attribute on all session cookies. Use 'Strict' or 'Lax' to prevent CSRF attacks."
                                            })
                                        
                                        break
                            
                    except Exception as e:
                        logger.warning(
                            f"Error checking login endpoint {login_url}",
                            extra={
                                "url": login_url,
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
        return { "type": "error", "severity": Severity.INFO, "title": "Authentication Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
