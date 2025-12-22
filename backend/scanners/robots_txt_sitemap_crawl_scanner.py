import asyncio
import uuid
from typing import List, Optional, Dict, Any
import httpx
from backend.utils import get_http_client
from urllib.parse import urljoin, urlparse
import re
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from bs4 import BeautifulSoup
import logging

from .base_scanner import BaseScanner
from ..config_types.models import ScanInput, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class RobotsTxtSitemapCrawlScanner(BaseScanner):
    """
    A scanner module for analyzing robots.txt and sitemap files to identify
    potentially sensitive information and misconfigurations.
    """

    metadata = {
        "name": "Robots.txt and Sitemap Scanner",
        "description": "Analyzes robots.txt and sitemap files for sensitive information and misconfigurations.",
        "owasp_category": "A01:2021 - Broken Access Control",
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
        Analyzes robots.txt and sitemap files for sensitive information and misconfigurations.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings related to robots.txt and sitemap analysis.
        """
        findings: List[Dict] = []
        base_url = target.rstrip('/')
        robots_url = f"{base_url}/robots.txt"
        sitemap_url = f"{base_url}/sitemap.xml"

        try:
            async with get_http_client(follow_redirects=True, timeout=30) as client:
                # Check robots.txt
                try:
                    response = await client.get(robots_url)
                    if response.status_code == 200:
                        robots_content = response.text
                        findings.extend(self._analyze_robots_txt(robots_content, robots_url))
                    else:
                        logger.warning("robots.txt not found", extra={
                            "url": robots_url,
                            "status_code": response.status_code
                        })
                except httpx.RequestError as e:
                    logger.warning("Could not fetch robots.txt", extra={
                        "url": robots_url,
                        "error": str(e)
                    })
                except Exception as e:
                    logger.error("Error analyzing robots.txt", extra={
                        "url": robots_url,
                        "error": str(e)
                    }, exc_info=True)

                # Check sitemap.xml
                try:
                    response = await client.get(sitemap_url)
                    if response.status_code == 200:
                        sitemap_content = response.text
                        findings.extend(self._analyze_sitemap(sitemap_content, sitemap_url))
                    else:
                        logger.warning("sitemap.xml not found", extra={
                            "url": sitemap_url,
                            "status_code": response.status_code
                        })
                except httpx.RequestError as e:
                    logger.warning("Could not fetch sitemap.xml", extra={
                        "url": sitemap_url,
                        "error": str(e)
                    })
                except Exception as e:
                    logger.error("Error analyzing sitemap.xml", extra={
                        "url": sitemap_url,
                        "error": str(e)
                    }, exc_info=True)

        except Exception as e:
            logger.error("Unexpected error during scan", extra={
                "target": target,
                "error": str(e)
            }, exc_info=True)

        logger.info("Completed robots.txt and sitemap scan", extra={
            "target": target,
            "findings_count": len(findings)
        })
        return findings

    def _analyze_robots_txt(self, content: str, url: str) -> List[Dict]:
        """
        Analyzes robots.txt content for potential security issues.
        """
        findings: List[Dict] = []
        sensitive_patterns = [
            r'/admin',
            r'/backup',
            r'/config',
            r'/database',
            r'/debug',
            r'/dev',
            r'/internal',
            r'/private',
            r'/secret',
            r'/test',
            r'/tmp',
            r'/upload',
            r'/user',
            r'/wp-',
            r'\.git',
            r'\.env',
            r'\.sql',
            r'\.bak',
            r'\.log'
        ]

        # Check for sensitive paths in Disallow rules
        for line in content.splitlines():
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                for pattern in sensitive_patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        findings.append({
                            "type": "sensitive_path_exposed",
                            "severity": Severity.MEDIUM,
                            "title": "Sensitive Path Exposed in robots.txt",
                            "description": f"A sensitive path '{path}' is explicitly disallowed in robots.txt, which may reveal internal structure.",
                            "evidence": {
                                "path": path,
                                "pattern": pattern,
                                "line": line.strip()
                            },
                            "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                            "recommendation": "Review robots.txt for sensitive path disclosures. Consider using more generic patterns or removing sensitive paths entirely.",
                            "affected_url": url
                        })

        # Check for missing User-agent
        if not any(line.lower().startswith('user-agent:') for line in content.splitlines()):
            findings.append({
                "type": "missing_user_agent",
                "severity": Severity.LOW,
                "title": "Missing User-agent in robots.txt",
                "description": "The robots.txt file does not specify any User-agent directives.",
                "evidence": {
                    "content": content
                },
                "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                "recommendation": "Add appropriate User-agent directives to robots.txt to properly control crawler access.",
                "affected_url": url
            })

        return findings

    def _analyze_sitemap(self, content: str, url: str) -> List[Dict]:
        """
        Analyzes sitemap.xml content for potential security issues.
        """
        findings: List[Dict] = []
        sensitive_patterns = [
            r'/admin',
            r'/backup',
            r'/config',
            r'/database',
            r'/debug',
            r'/dev',
            r'/internal',
            r'/private',
            r'/secret',
            r'/test',
            r'/tmp',
            r'/upload',
            r'/user',
            r'/wp-',
            r'\.git',
            r'\.env',
            r'\.sql',
            r'\.bak',
            r'\.log'
        ]

        try:
            soup = BeautifulSoup(content, 'xml')
            urls = soup.find_all('url')
            
            for url_tag in urls:
                loc = url_tag.find('loc')
                if loc and loc.text:
                    path = urlparse(loc.text).path
                    for pattern in sensitive_patterns:
                        if re.search(pattern, path, re.IGNORECASE):
                            findings.append({
                                "type": "sensitive_path_in_sitemap",
                                "severity": Severity.MEDIUM,
                                "title": "Sensitive Path Exposed in Sitemap",
                                "description": f"A sensitive path '{path}' is exposed in the sitemap.xml file.",
                                "evidence": {
                                    "path": path,
                                    "pattern": pattern,
                                    "url": loc.text
                                },
                                "owasp_category": OwaspCategory.BROKEN_ACCESS_CONTROL,
                                "recommendation": "Remove sensitive paths from sitemap.xml and ensure they are properly protected.",
                                "affected_url": url
                            })
        except Exception as e:
            logger.error("Error parsing sitemap.xml", extra={
                "url": url,
                "error": str(e)
            }, exc_info=True)

        return findings 

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Robots.txt/Sitemap Crawl Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
