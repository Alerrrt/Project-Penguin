# -*- coding: utf-8 -*-
import asyncio
import uuid
from typing import List, Optional, Dict, Any
import logging
import httpx

from .base_scanner import BaseScanner
from ..config_types.models import ScanInput, Severity, OwaspCategory
from backend.scanners.scanner_registry import ScannerRegistry
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from backend.utils import get_http_client
from urllib.parse import urljoin
from datetime import datetime

logger = logging.getLogger(__name__)

class BackupAndSensitiveFileFinderScanner(BaseScanner):
    """
    A scanner module for finding exposed backup and sensitive configuration files.
    """

    metadata = {
        "name": "Backup & Sensitive File Finder",
        "description": "Finds exposed backup and sensitive configuration files by probing common file paths.",
        "owasp_category": "A05:2021 - Security Misconfiguration",
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
        findings: List[Dict] = []
        target_url = target
        logger.info("Starting Backup & Sensitive File scan", extra={
            "target": target_url,
            "scanner": self.__class__.__name__
        })

        common_files = [
            "/index.php.bak", "/index.html.bak", "/wp-config.php.bak",
            "/config.bak", "/config.old",
            "/.env", "/.env.bak",
            "/database.sql", "/backup.sql",
            "/.git/config", "/.git/HEAD",
            "/docker-compose.yml", "/Dockerfile",
            "/web.config.bak", # IIS related
            "/admin.bak", "/user.sql",
            "/config.json.bak", "/credentials.txt",
        ]

        try:
            async with get_http_client(follow_redirects=True, timeout=30) as client:
                tasks = []
                for file_path in common_files:
                    full_url = urljoin(target_url, file_path)
                    tasks.append(self._check_file_existence(client, full_url, file_path))
                results = await asyncio.gather(*tasks)
                for result in results:
                    if result:
                        findings.append(result)
        except Exception as e:
            logger.error("Unexpected error during backup & sensitive file scan", extra={
                "target": target_url,
                "error": str(e),
                "scanner": self.__class__.__name__
            }, exc_info=True)

        logger.info("Finished Backup & Sensitive File scan", extra={
            "target": target_url,
            "findings_count": len(findings),
            "scanner": self.__class__.__name__
        })
        return findings

    async def _check_file_existence(self, client: httpx.AsyncClient, url: str, file_path: str) -> Optional[Dict]:
        try:
            response = await client.get(url, timeout=10)
            if response.status_code == 200:
                logger.info("Sensitive file found", extra={
                    "url": url,
                    "file_path": file_path,
                    "status_code": response.status_code,
                    "scanner": self.__class__.__name__
                })
                return {
                    "type": "exposed_sensitive_file",
                    "severity": Severity.HIGH,
                    "title": "Exposed Sensitive File",
                    "description": f"Potentially sensitive file '{file_path}' found publicly accessible. Status code: {response.status_code}",
                    "evidence": {
                        "url": url,
                        "status_code": response.status_code,
                        "response_length": len(response.text),
                        "file_path_attempted": file_path,
                        "content_type": response.headers.get('content-type', 'unknown'),
                        "response_snippet": response.text[:200] if response.text else None
                    },
                    "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                    "recommendation": "Remove or restrict access to sensitive files and backups. Do not store sensitive information in publicly accessible locations. Implement proper access controls and file permissions."
                }
        except httpx.RequestError as e:
            logger.warning("Error checking file existence", extra={
                "url": url,
                "file_path": file_path,
                "error": str(e),
                "scanner": self.__class__.__name__
            })
        except Exception as e:
            logger.error("Unexpected error in file existence check", extra={
                "url": url,
                "file_path": file_path,
                "error": str(e),
                "scanner": self.__class__.__name__
            }, exc_info=True)
        return None

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Backup and Sensitive File Finder Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }

def register(scanner_registry: ScannerRegistry) -> None:
    scanner_registry.register("backup_sensitive_file_finder", BackupAndSensitiveFileFinderScanner)
