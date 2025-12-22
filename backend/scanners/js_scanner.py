import asyncio
import uuid
import httpx
import json
from urllib.parse import urljoin, urlparse
from typing import List, Optional, Dict, Any
from datetime import datetime
from bs4 import BeautifulSoup
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils import get_http_client
from backend.utils.secrets import scan_text_for_secrets
from backend.utils.crawler import seed_urls
from backend.utils.logging_config import get_context_logger
import logging

from .base_scanner import BaseScanner
from ..config_types.models import ScanInput, Severity, OwaspCategory
from .js_scanner_utils import run_retire_js

logger = logging.getLogger(__name__)

class JsScanner(BaseScanner):
    """
    A scanner module for identifying known JavaScript library vulnerabilities
    using retire.js.
    """

    metadata = {
        "name": "JavaScript Library Scanner",
        "description": "Identifies known JavaScript library vulnerabilities using retire.js.",
        "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
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
            results = await self._perform_scan(scan_input.target, scan_input.options)
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
        Crawls the target URL for JavaScript files, downloads them,
        and scans them using retire.js.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for identified JS library vulnerabilities.
        """
        findings: List[Dict] = []
        target_url = target
        base_domain = urlparse(target_url).netloc
        logger.info(f"Starting JavaScript Library scan for {target_url}")

        discovered_js_urls = set()

        try:
            timeout = float(options.get("timeout", 30))
            use_seeds = bool(options.get("use_seeds", True))
            max_urls = int(options.get("max_urls", 6))
            async with get_http_client(follow_redirects=True, timeout=timeout) as client:
                logger.debug(f"Fetching HTML from {target_url}")
                try:
                    response = await client.get(target_url)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'lxml')
                    
                    for script_tag in soup.find_all('script', src=True):
                        src = script_tag['src']
                        full_js_url = urljoin(target_url, src)
                        
                        parsed_js_url = urlparse(full_js_url)
                        if parsed_js_url.scheme in ['http', 'https'] and (parsed_js_url.netloc == base_domain or not parsed_js_url.netloc):
                            discovered_js_urls.add(full_js_url)
                            logger.debug(f"Discovered JS URL: {full_js_url}")
                except httpx.RequestError as e:
                    logger.warning(f"Could not fetch target for JS links", extra={
                        "target": target_url,
                        "error": str(e)
                    })
                except Exception as e:
                    logger.error(f"Error parsing HTML for JS links", extra={
                        "target": target_url,
                        "error": str(e)
                    }, exc_info=True)

                # Optionally crawl a few more pages for extra scripts
                if use_seeds:
                    try:
                        for page in await seed_urls(target_url, max_urls=max_urls):
                            try:
                                r2 = await client.get(page)
                                s2 = BeautifulSoup(r2.text, 'lxml')
                                for script_tag in s2.find_all('script', src=True):
                                    src = script_tag['src']
                                    full_js_url = urljoin(page, src)
                                    parsed_js_url = urlparse(full_js_url)
                                    if parsed_js_url.scheme in ['http', 'https'] and (parsed_js_url.netloc == base_domain or not parsed_js_url.netloc):
                                        discovered_js_urls.add(full_js_url)
                            except Exception:
                                continue
                    except Exception:
                        pass

                js_download_tasks = []
                for js_url in discovered_js_urls:
                    js_download_tasks.append(self._download_js_file(client, js_url))
                
                downloaded_js_files = await asyncio.gather(*js_download_tasks)

                retire_scan_tasks = []
                for js_url, js_content in downloaded_js_files:
                    if js_content:
                        retire_scan_tasks.append(self._scan_js_content_with_retire(js_url, js_content))
                
                retire_results = await asyncio.gather(*retire_scan_tasks)

                for result_list in retire_results:
                    for retire_finding in result_list:
                        if retire_finding:
                            mapped_finding = self._map_retire_to_finding(retire_finding)
                            if mapped_finding:
                                findings.append(mapped_finding)

                # Secrets scanning pass on JS contents (limited)
                for js_url, js_content in downloaded_js_files:
                    if not js_content:
                        continue
                    secrets = scan_text_for_secrets(js_content, max_findings=5)
                    for s in secrets:
                        findings.append({
                            "type": "hardcoded_secret",
                            "severity": Severity.CRITICAL if s["severity"].lower()=="critical" else Severity.HIGH if s["severity"].lower()=="high" else Severity.MEDIUM,
                            "title": f"Potential Secret: {s['name']}",
                            "description": "Potential credential/token pattern detected in a JavaScript resource.",
                            "evidence": {"file_url": js_url, "match": s["match"]},
                            "owasp_category": OwaspCategory.SENSITIVE_DATA_EXPOSURE if hasattr(OwaspCategory, 'SENSITIVE_DATA_EXPOSURE') else OwaspCategory.SECURITY_MISCONFIGURATION,
                            "remediation": "Remove hardcoded secrets; use environment variables or secure vaults, and rotate compromised tokens.",
                            "affected_url": js_url,
                        })

        except Exception as e:
            logger.error(f"Unexpected error during JavaScript scan", extra={
                "target": target_url,
                "error": str(e)
            }, exc_info=True)

        logger.info(f"Completed JavaScript Library scan for {target_url}. Found {len(findings)} issues.")
        return findings

    async def _download_js_file(self, client: httpx.AsyncClient, js_url: str) -> tuple[str, Optional[str]]:
        """
        Downloads a JavaScript file, skipping if it's larger than 1MB.
        Returns the URL and content, or None if skipped/failed.
        """
        MAX_JS_FILE_SIZE = 1 * 1024 * 1024 # 1 MB
        try:
            logger.debug(f"Downloading JS file: {js_url}")
            async with client.stream("GET", js_url, timeout=30) as response:
                response.raise_for_status()
                content_length = response.headers.get('content-length')
                if content_length and int(content_length) > MAX_JS_FILE_SIZE:
                    logger.warning(f"Skipping large JS file", extra={
                        "url": js_url,
                        "size_mb": int(content_length)/1024/1024
                    })
                    return js_url, None
                
                js_content = await response.text()
                return js_url, js_content
        except httpx.RequestError as e:
            logger.warning(f"Could not download JS file", extra={
                "url": js_url,
                "error": str(e)
            })
            return js_url, None
        except Exception as e:
            logger.error(f"Error downloading JS file", extra={
                "url": js_url,
                "error": str(e)
            }, exc_info=True)
            return js_url, None

    async def _scan_js_content_with_retire(self, js_url: str, js_content: str) -> List[dict]:
        """
        Runs retire.js on the JS content and returns its raw findings.
        Adds the original URL to each finding for context.
        """
        try:
            retire_findings = await run_retire_js(js_content)
            for finding in retire_findings:
                finding['affected_url_original'] = js_url
            return retire_findings
        except Exception as e:
            logger.error(f"Error running retire.js scan", extra={
                "url": js_url,
                "error": str(e)
            }, exc_info=True)
            return []

    def _map_retire_to_finding(self, retire_finding: Dict[str, Any]) -> Optional[Dict]:
        """
        Maps a single retire.js finding to our internal finding format.
        """
        try:
            file_path = retire_finding.get("file", "Unknown File")
            original_url = retire_finding.get("affected_url_original", file_path)

            for result in retire_finding.get("results", []):
                component = result.get("component", "Unknown Component")
                version = result.get("version", "Unknown Version")

                for vuln_data in result.get("vulnerabilities", []):
                    severity_str = vuln_data.get("severity", "info").capitalize()
                    mapped_severity = getattr(Severity, severity_str.upper(), Severity.INFO)
                    
                    cves = vuln_data.get("identifiers", {}).get("CVE", [])
                    cve_id = cves[0] if cves else None

                    advisories = vuln_data.get("info", [])
                    advisory_link = advisories[0] if advisories else None

                    summary = vuln_data.get("summary", "No summary provided.")

                    description = (
                        f"Vulnerable JavaScript library detected: {component} (Version: {version}). "
                        f"Details: {summary}"
                    )

                    technical_details = json.dumps(vuln_data, indent=2)
                    
                    return {
                        "type": "vulnerable_js_library",
                        "severity": mapped_severity,
                        "title": f"Vulnerable JS: {component} v{version}",
                        "description": description,
                        "evidence": {
                            "library": component,
                            "version": version,
                            "cves": cves,
                            "advisory_link": advisory_link,
                            "file_url": original_url,
                            "technical_details": technical_details
                        },
                        "owasp_category": OwaspCategory.VULNERABLE_AND_OUTDATED_COMPONENTS,
                        "recommendation": (
                            f"Upgrade {component} to a non-vulnerable version. "
                            f"Consult advisory: {advisory_link}" if advisory_link else f"Consult official documentation for {component}."
                        ),
                        "affected_url": original_url,
                        "cwe_id": cve_id
                    }
        except Exception as e:
            logger.error(f"Error mapping retire.js finding", extra={
                "finding": retire_finding,
                "error": str(e)
            }, exc_info=True)
        return None 

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "JavaScript Scanner Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
