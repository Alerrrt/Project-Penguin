from datetime import datetime
from typing import List, Dict, Any
import asyncio
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity, OwaspCategory
import logging
from backend.utils import get_http_client

logger = logging.getLogger(__name__)

class AuthenticationBruteForceCredentialStuffingScanner(BaseScanner):
    """
    A scanner module for detecting vulnerabilities to brute force and credential stuffing attacks.
    """

    metadata = {
        "name": "Authentication Brute Force and Credential Stuffing",
        "description": "Detects vulnerabilities to brute force and credential stuffing attacks by testing authentication mechanisms.",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="authentication_brute_force_credential_stuffing_scanner")
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
        Perform the actual brute force and credential stuffing vulnerability scan.
        
        Args:
            target: Target URL to scan
            options: Scan options including timeout and test credentials
            
        Returns:
            List of findings containing brute force and credential stuffing vulnerabilities
        """
        findings = []
        timeout = options.get('timeout', 10)
        max_attempts = options.get('max_attempts', 10)
        delay = options.get('delay', 1)  # Delay between attempts in seconds
        
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
        
        # Common credential stuffing payloads
        credential_payloads = options.get('credential_payloads', [
            # Common username/password combinations
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'admin', 'password': '123456'},
            {'username': 'admin', 'password': 'admin123'},
            {'username': 'admin', 'password': 'qwerty'},
            {'username': 'admin', 'password': 'letmein'},
            {'username': 'admin', 'password': 'welcome'},
            {'username': 'admin', 'password': 'monkey'},
            {'username': 'admin', 'password': 'dragon'},
            {'username': 'admin', 'password': 'baseball'},
            
            # Common email/password combinations
            {'email': 'admin@example.com', 'password': 'admin'},
            {'email': 'admin@example.com', 'password': 'password'},
            {'email': 'admin@example.com', 'password': '123456'},
            {'email': 'admin@example.com', 'password': 'admin123'},
            {'email': 'admin@example.com', 'password': 'qwerty'},
            
            # Common username variations
            {'username': 'administrator', 'password': 'admin'},
            {'username': 'root', 'password': 'root'},
            {'username': 'system', 'password': 'system'},
            {'username': 'user', 'password': 'user'},
            {'username': 'guest', 'password': 'guest'}
        ])
        
        async with get_http_client(timeout=timeout) as client:
            try:
                # Check for login endpoints
                for endpoint in login_endpoints:
                    login_url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
                    
                    try:
                        # Check if endpoint exists
                        response = await client.get(login_url)
                        
                        if response.status_code != 404:
                            # Test for credential stuffing
                            success_count = 0
                            failure_count = 0
                            start_time = datetime.now()
                            
                            for i, payload in enumerate(credential_payloads[:max_attempts]):
                                try:
                                    # Try different content types
                                    content_types = [
                                        'application/json',
                                        'application/x-www-form-urlencoded',
                                        'multipart/form-data'
                                    ]
                                    
                                    for content_type in content_types:
                                        try:
                                            if content_type == 'application/json':
                                                login_response = await client.post(
                                                    login_url,
                                                    json=payload,
                                                    headers={'Content-Type': content_type}
                                                )
                                            else:
                                                login_response = await client.post(
                                                    login_url,
                                                    data=payload,
                                                    headers={'Content-Type': content_type}
                                                )
                                            
                                            # Check response status
                                            if login_response.status_code == 200:
                                                success_count += 1
                                                
                                                # Check for successful login indicators
                                                success_indicators = [
                                                    'welcome',
                                                    'dashboard',
                                                    'profile',
                                                    'logout',
                                                    'account',
                                                    'success'
                                                ]
                                                
                                                if any(indicator in login_response.text.lower() for indicator in success_indicators):
                                                    findings.append({
                                                        "type": "credential_stuffing_vulnerability",
                                                        "severity": Severity.HIGH,
                                                        "title": "Credential Stuffing Vulnerability",
                                                        "description": "Application is vulnerable to credential stuffing attacks.",
                                                        "evidence": {
                                                            "url": login_url,
                                                            "payload": payload,
                                                            "content_type": content_type,
                                                            "status_code": login_response.status_code,
                                                            "response_snippet": login_response.text[:200]
                                                        },
                                                        "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                                        "recommendation": "Implement strong authentication mechanisms. Use CAPTCHA, rate limiting, and account lockout. Consider implementing multi-factor authentication."
                                                    })
                                                    break
                                            else:
                                                failure_count += 1
                                            
                                            # Check for rate limiting headers
                                            if 'X-RateLimit-Remaining' in login_response.headers:
                                                remaining = int(login_response.headers['X-RateLimit-Remaining'])
                                                if remaining <= 0:
                                                    findings.append({
                                                        "type": "credential_stuffing_protection",
                                                        "severity": Severity.LOW,
                                                        "title": "Rate Limiting Detected",
                                                        "description": "Application implements rate limiting for login attempts.",
                                                        "evidence": {
                                                            "url": login_url,
                                                            "header": "X-RateLimit-Remaining",
                                                            "value": remaining
                                                        },
                                                        "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                                        "recommendation": "Consider implementing progressive delays or account lockout after multiple failed attempts."
                                                    })
                                                    break
                                            
                                        except Exception as e:
                                            logger.warning(
                                                f"Error testing content type {content_type} for {login_url}",
                                                extra={
                                                    "url": login_url,
                                                    "content_type": content_type,
                                                    "error": str(e)
                                                }
                                            )
                                            continue
                                    
                                    # Add delay between attempts
                                    await asyncio.sleep(delay)
                                    
                                except Exception as e:
                                    logger.warning(
                                        f"Error testing payload for {login_url}",
                                        extra={
                                            "url": login_url,
                                            "error": str(e)
                                        }
                                    )
                                    continue
                            
                            # Calculate attempt rate
                            end_time = datetime.now()
                            duration = (end_time - start_time).total_seconds()
                            attempt_rate = (success_count + failure_count) / duration if duration > 0 else 0
                            
                            # Check if rate limiting is effective
                            if attempt_rate > 2:  # More than 2 attempts per second
                                findings.append({
                                    "type": "credential_stuffing_vulnerability",
                                    "severity": Severity.HIGH,
                                    "title": "Ineffective Rate Limiting",
                                    "description": "Application allows too many login attempts in a short time period.",
                                    "evidence": {
                                        "url": login_url,
                                        "attempt_rate": attempt_rate,
                                        "success_count": success_count,
                                        "failure_count": failure_count,
                                        "duration": duration
                                    },
                                    "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                    "recommendation": "Implement stronger rate limiting. Consider progressive delays, CAPTCHA, or account lockout after multiple failed attempts."
                                })
                            
                            # Check for account lockout
                            if success_count > 0 and failure_count >= 3:
                                findings.append({
                                    "type": "credential_stuffing_vulnerability",
                                    "severity": Severity.HIGH,
                                    "title": "Missing Account Lockout",
                                    "description": "Application does not implement account lockout after multiple failed attempts.",
                                    "evidence": {
                                        "url": login_url,
                                        "success_count": success_count,
                                        "failure_count": failure_count
                                    },
                                    "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                    "recommendation": "Implement account lockout after a certain number of failed attempts. Consider temporary lockout with increasing duration."
                                })
                            
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
        return { "type": "error", "severity": Severity.INFO, "title": "Authentication Brute Force/Credential Stuffing Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
