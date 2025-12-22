from datetime import datetime
from typing import List, Dict, Any
from backend.utils import get_http_client
import asyncio
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity, OwaspCategory
import logging

logger = logging.getLogger(__name__)

class AuthenticationBruteForceScanner(BaseScanner):
    """
    A scanner module for detecting vulnerabilities to brute force attacks.
    """

    metadata = {
        "name": "Authentication Brute Force",
        "description": "Detects vulnerabilities to brute force attacks by testing password policies and rate limiting.",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="authentication_brute_force_scanner")
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
        Perform the actual brute force vulnerability scan.
        
        Args:
            target: Target URL to scan
            options: Scan options including timeout and test credentials
            
        Returns:
            List of findings containing brute force vulnerabilities
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
        
        # Test credentials for brute force
        test_credentials = options.get('test_credentials', [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'admin', 'password': '123456'},
            {'username': 'admin', 'password': 'admin123'},
            {'username': 'admin', 'password': 'qwerty'},
            {'username': 'admin', 'password': 'letmein'},
            {'username': 'admin', 'password': 'welcome'},
            {'username': 'admin', 'password': 'monkey'},
            {'username': 'admin', 'password': 'dragon'},
            {'username': 'admin', 'password': 'baseball'}
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
                            # Test for rate limiting
                            success_count = 0
                            failure_count = 0
                            start_time = datetime.now()
                            
                            for i, creds in enumerate(test_credentials[:max_attempts]):
                                try:
                                    login_response = await client.post(
                                        login_url,
                                        json=creds,
                                        headers={'Content-Type': 'application/json'}
                                    )
                                    
                                    # Check response status
                                    if login_response.status_code == 200:
                                        success_count += 1
                                    else:
                                        failure_count += 1
                                    
                                    # Check for rate limiting headers
                                    if 'X-RateLimit-Remaining' in login_response.headers:
                                        remaining = int(login_response.headers['X-RateLimit-Remaining'])
                                        if remaining <= 0:
                                            findings.append({
                                                "type": "brute_force_protection",
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
                                    
                                    # Add delay between attempts
                                    await asyncio.sleep(delay)
                                    
                                except Exception as e:
                                    logger.warning(
                                        f"Error testing credentials for {login_url}",
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
                                    "type": "brute_force_vulnerability",
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
                                    "type": "brute_force_vulnerability",
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
        return { "type": "error", "severity": Severity.INFO, "title": "Authentication Brute Force Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
