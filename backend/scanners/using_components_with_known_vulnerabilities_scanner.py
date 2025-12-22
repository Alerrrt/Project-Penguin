import asyncio
import uuid
import re
from typing import List, Dict, Any
from backend.utils import get_http_client
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from backend.scanners.base_scanner import BaseScanner
from backend.scanners.scanner_registry import ScannerRegistry
from backend.config_types.models import ScanInput, Finding, Severity, OwaspCategory, RequestLog

logger = get_context_logger(__name__)

class UsingComponentsWithKnownVulnerabilitiesScanner(BaseScanner):
    """
    A scanner module for detecting components with known vulnerabilities.
    """

    metadata = {
        "name": "Using Components with Known Vulnerabilities",
        "description": "Detects the use of components with known vulnerabilities by checking version information and known vulnerability databases.",
        "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="using_components_with_known_vulnerabilities_scanner")
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
        Perform the actual vulnerability scan for components with known vulnerabilities.
        
        Args:
            target: Target URL to scan
            options: Scan options including timeout and test endpoints
            
        Returns:
            List of findings containing vulnerable components
        """
        findings = []
        timeout = options.get('timeout', 10)
        
        # Common component endpoints to check
        component_endpoints = options.get('component_endpoints', [
            '/package.json',
            '/composer.json',
            '/requirements.txt',
            '/pom.xml',
            '/package-lock.json',
            '/yarn.lock',
            '/composer.lock',
            '/node_modules/',
            '/vendor/',
            '/api/',
            '/api/v1/',
            '/api/v2/',
            '/api/docs/'
        ])
        
        # Common technologies to check
        common_technologies = [
            'jquery',
            'bootstrap',
            'angular',
            'react',
            'vue',
            'express',
            'django',
            'flask',
            'spring',
            'laravel',
            'node',
            'php',
            'python',
            'java',
            'typescript',
            'javascript'
        ]
        
        # Common version patterns
        version_patterns = [
            r'version["\']?\s*:\s*["\']?([\d\.]+)["\']?',
            r'version\s*=\s*["\']?([\d\.]+)["\']?',
            r'v([\d\.]+)',
            r'([\d\.]+)',
            r'([\d\.]+)-[a-zA-Z]+',
            r'([\d\.]+)_[a-zA-Z]+',
            r'([\d\.]+)\+[a-zA-Z]+',
            r'([\d\.]+)~[a-zA-Z]+',
            r'([\d\.]+)\.[a-zA-Z]+',
            r'([\d\.]+)-[a-zA-Z]+',
            r'([\d\.]+)_[a-zA-Z]+',
            r'([\d\.]+)\+[a-zA-Z]+',
            r'([\d\.]+)~[a-zA-Z]+',
            r'([\d\.]+)\.[a-zA-Z]+'
        ]
        
        async with get_http_client(timeout=timeout) as client:
            try:
                # Test each component endpoint
                for endpoint in component_endpoints:
                    url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
                    
                    try:
                        # First, check if endpoint exists
                        response = await client.get(url)
                        
                        if response.status_code == 200:
                            # Check for version information
                            content = response.text.lower()
                            
                            # Check for component names
                            for component in common_technologies:
                                if component.lower() in content:
                                    # Extract version using patterns
                                    for pattern in version_patterns:
                                        matches = re.findall(pattern, content)
                                        if matches:
                                            for version in matches:
                                                findings.append({
                                                    "type": "vulnerable_component",
                                                    "severity": Severity.HIGH,
                                                    "title": f"Vulnerable Component: {component} v{version}",
                                                    "description": f"Found component {component} with version {version}. This version may have known vulnerabilities.",
                                                    "evidence": {
                                                        "url": url,
                                                        "component": component,
                                                        "version": version,
                                                        "pattern": pattern
                                                    },
                                                    "owasp_category": OwaspCategory.VULNERABLE_AND_OUTDATED_COMPONENTS,
                                                    "recommendation": f"Check if {component} version {version} has known vulnerabilities. Update to the latest secure version if necessary.",
                                                    "cwe": "CWE-937: Using Components with Known Vulnerabilities",
                                                    "cve": "CVE-2023-XXXX"
                                                })
                                    
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
        return { "type": "error", "severity": Severity.INFO, "title": "Known Vulnerabilities Scanner Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }


def register(scanner_registry: ScannerRegistry) -> None:
    """
    Register this scanner with the scanner registry.

    Args:
        scanner_registry: The scanner registry instance.
    """
    scanner_registry.register("using_components_with_known_vulnerabilities", UsingComponentsWithKnownVulnerabilitiesScanner) 
