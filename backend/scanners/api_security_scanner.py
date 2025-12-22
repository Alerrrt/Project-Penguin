from datetime import datetime
from typing import List, Dict, Any
from backend.utils import get_http_client
import json
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity, OwaspCategory

logger = get_context_logger(__name__)

class ApiSecurityScanner(BaseScanner):
    """
    A scanner module for detecting API security vulnerabilities.
    """

    metadata = {
        "name": "API Security",
        "description": "Detects API security vulnerabilities including improper API versioning, missing rate limiting, and insecure API endpoints.",
        "owasp_category": "A01:2021 - Broken Access Control",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="api_security_scanner")
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        start_time = datetime.now()
        scan_id = f"{self.__class__.__name__}_{start_time.strftime('%Y%m%d_%H%M%S')}"
        try:
            logger.info(
                "Scan started",
                extra={
                    "scanner": self.__class__.__name__,
                    "scan_id": scan_id,
                    "target": scan_input.target,
                    "options": scan_input.options
                }
            )
            results = await self._perform_scan(scan_input.target, scan_input.options)
            self._update_metrics(True, start_time)
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
            self._update_metrics(False, start_time)
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
            return [self._create_error_finding(f"API Security scan failed: {e}")]

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        findings = []
        timeout = options.get('timeout', 10)
        api_endpoints = options.get('api_endpoints', [
            '/api', '/api/v1', '/api/v2', '/api/v3', '/api/docs', '/api/swagger', '/api/openapi', '/api/health', '/api/status', '/api/metrics', '/api/version', '/api/info', '/api/users', '/api/auth', '/api/token', '/api/oauth', '/api/login', '/api/register', '/api/profile', '/api/settings'
        ])
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        version_headers = [
            'Accept-Version', 'API-Version', 'X-API-Version', 'Version'
        ]
        version_values = ['1', '2', '3', 'latest', 'stable', 'beta', 'alpha']
        async with get_http_client(timeout=timeout) as client:
            try:
                for endpoint in api_endpoints:
                    url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
                    try:
                        response = await client.get(url)
                        if response.status_code != 404:
                            for method in http_methods:
                                try:
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
                                    if method_response.status_code == 200:
                                        findings.append({
                                            "type": "api_security",
                                            "severity": Severity.MEDIUM,
                                            "title": "Missing API Version Header",
                                            "description": f"API endpoint is accessible without version header using {method} method.",
                                            "evidence": {
                                                "url": url,
                                                "method": method,
                                                "status_code": method_response.status_code,
                                                "response_length": len(method_response.text)
                                            },
                                            "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                                            "recommendation": "Implement proper API versioning using version headers. This helps maintain backward compatibility and allows for graceful deprecation of old versions."
                                        })
                                    for header in version_headers:
                                        for version in version_values:
                                            try:
                                                headers = {header: version}
                                                if method == 'GET':
                                                    version_response = await client.get(url, headers=headers)
                                                elif method == 'POST':
                                                    version_response = await client.post(url, headers=headers)
                                                elif method == 'PUT':
                                                    version_response = await client.put(url, headers=headers)
                                                elif method == 'DELETE':
                                                    version_response = await client.delete(url, headers=headers)
                                                elif method == 'PATCH':
                                                    version_response = await client.patch(url, headers=headers)
                                                elif method == 'OPTIONS':
                                                    version_response = await client.options(url, headers=headers)
                                                elif method == 'HEAD':
                                                    version_response = await client.head(url, headers=headers)
                                            except Exception as e:
                                                logger.warning(f"Version header test failed for {header}: {e}")
                                except Exception as e:
                                    logger.warning(f"HTTP method test failed for {method}: {e}")
                    except Exception as e:
                        logger.warning(f"API endpoint test failed for {url}: {e}")
            except Exception as e:
                logger.error(f"API Security scan failed during endpoint testing: {e}")
                findings.append(self._create_error_finding(f"API Security scan failed during endpoint testing: {e}"))
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return {
            "type": "error",
            "severity": Severity.INFO,
            "title": "API Security Scanner Error",
            "description": description,
            "location": "Scanner",
            "cwe": "N/A",
            "remediation": "N/A",
            "confidence": 0,
            "cvss": 0
        } 
