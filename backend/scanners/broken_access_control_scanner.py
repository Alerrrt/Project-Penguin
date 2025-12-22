from datetime import datetime
from typing import List, Dict, Any
from backend.utils import get_http_client
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity, OwaspCategory
import logging

logger = logging.getLogger(__name__)

class BrokenAccessControlScanner(BaseScanner):
    """
    A scanner module for detecting broken access control vulnerabilities.
    """

    metadata = {
        "name": "Broken Access Control",
        "description": "Detects broken access control vulnerabilities by testing various access control mechanisms.",
        "owasp_category": "A01:2021 - Broken Access Control",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="broken_access_control_scanner")
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
        Perform the actual broken access control vulnerability scan.
        
        Args:
            target: Target URL to scan
            options: Scan options including timeout and test endpoints
            
        Returns:
            List of findings containing broken access control vulnerabilities
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
            '/api/profile',
            '/api/management',
            '/api/config',
            '/api/system',
            '/api/backup',
            '/api/logs',
            '/api/debug',
            '/api/test',
            '/api/development'
        ])
        
        # Common HTTP methods to test
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        
        # Common user roles to test
        user_roles = [
            'admin',
            'user',
            'guest',
            'anonymous',
            'test',
            'developer',
            'manager',
            'support'
        ]
        
        async with get_http_client(timeout=timeout) as client:
            try:
                # Test each protected endpoint
                for endpoint in protected_endpoints:
                    url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
                    
                    try:
                        # First, check if endpoint exists
                        response = await client.get(url)
                        
                        if response.status_code != 404:
                            # Test each HTTP method
                            for method in http_methods:
                                try:
                                    # Test without authentication
                                    if method == 'GET':
                                        method_response = await client.get(url)
                                    elif method == 'POST':
                                        method_response = await client.post(url)
                                    elif method == 'PUT':
                                        method_response = await client.put(url)
                                    elif method == 'DELETE':
                                        method_response = await client.delete(url)
                                    elif method == 'PATCH':
                                        method_response = await client.patch(url)
                                    elif method == 'OPTIONS':
                                        method_response = await client.options(url)
                                    elif method == 'HEAD':
                                        method_response = await client.head(url)
                                    else:
                                        continue
                                    
                                    # Check if access is allowed without authentication
                                    if method_response.status_code == 200:
                                        findings.append({
                                            "type": "broken_access_control",
                                            "severity": Severity.HIGH,
                                            "title": "Missing Access Control",
                                            "description": f"Protected endpoint is accessible without authentication using {method} method.",
                                            "evidence": {
                                                "url": url,
                                                "method": method,
                                                "status_code": method_response.status_code,
                                                "response_length": len(method_response.text)
                                            },
                                            "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                                            "recommendation": "Implement proper access control checks. Ensure all protected endpoints require authentication and authorization."
                                        })
                                    
                                    # Test with different user roles
                                    for role in user_roles:
                                        try:
                                            # Add role-based headers
                                            headers = {
                                                'X-User-Role': role,
                                                'X-Role': role,
                                                'Role': role,
                                                'User-Role': role
                                            }
                                            
                                            if method == 'GET':
                                                role_response = await client.get(url, headers=headers)
                                            elif method == 'POST':
                                                role_response = await client.post(url, headers=headers)
                                            elif method == 'PUT':
                                                role_response = await client.put(url, headers=headers)
                                            elif method == 'DELETE':
                                                role_response = await client.delete(url, headers=headers)
                                            elif method == 'PATCH':
                                                role_response = await client.patch(url, headers=headers)
                                            elif method == 'OPTIONS':
                                                role_response = await client.options(url, headers=headers)
                                            elif method == 'HEAD':
                                                role_response = await client.head(url, headers=headers)
                                            else:
                                                continue
                                            
                                            # Check if access is allowed with unauthorized role
                                            if role_response.status_code == 200 and role != 'admin':
                                                findings.append({
                                                    "type": "broken_access_control",
                                                    "severity": Severity.HIGH,
                                                    "title": "Insufficient Role-Based Access Control",
                                                    "description": f"Protected endpoint is accessible with unauthorized role '{role}' using {method} method.",
                                                    "evidence": {
                                                        "url": url,
                                                        "method": method,
                                                        "role": role,
                                                        "status_code": role_response.status_code,
                                                        "response_length": len(role_response.text)
                                                    },
                                                    "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                                                    "recommendation": "Implement proper role-based access control. Ensure users can only access resources they are authorized to access."
                                                })
                                            
                                        except Exception as e:
                                            logger.warning(
                                                f"Error testing role {role} for {url}",
                                                extra={
                                                    "url": url,
                                                    "method": method,
                                                    "role": role,
                                                    "error": str(e)
                                                }
                                            )
                                            continue
                                    
                                except Exception as e:
                                    logger.warning(
                                        f"Error testing method {method} for {url}",
                                        extra={
                                            "url": url,
                                            "method": method,
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
        return { "type": "error", "severity": Severity.INFO, "title": "Broken Access Control Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
