import logging
import httpx
from typing import List, Dict, Any
from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity
from backend.utils import get_http_client
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class WaybackMachineScanner(BaseScanner):
    """
    A scanner module for querying the Wayback Machine for historical snapshots and URLs.
    """

    metadata = {
        "name": "Wayback Machine Historical Analysis",
        "description": "Discovers historical URLs and snapshots using the Wayback Machine API.",
        "owasp_category": "Informational",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        findings: List[Dict] = []
        try:
            domain = urlparse(target).netloc
            if not domain:
                return []

            # 1. Check for the most recent snapshot
            wayback_api = f"https://archive.org/wayback/available?url={domain}"
            async with get_http_client(timeout=15) as client:
                response = await client.get(wayback_api)
                if response.status_code == 200:
                    data = response.json()
                    snapshots = data.get("archived_snapshots", {})
                    if snapshots and "closest" in snapshots:
                        closest = snapshots["closest"]
                        findings.append({
                            "type": "recon",
                            "severity": Severity.RECON.value,
                            "title": "Historical Snapshot Available",
                            "description": f"The Wayback Machine has a snapshot from {closest.get('timestamp')}.",
                            "location": "Wayback Machine",
                            "category": "recon",
                            "evidence": closest.get('url'),
                            "remediation": "Review historical versions for sensitive information that may have been removed from the current site.",
                            "confidence": 100,
                            "cvss": 0.0
                        })

                # 2. Get a list of common historical URLs (limited to first 10 for performance)
                cdx_api = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=10&fl=original,timestamp"
                cdx_response = await client.get(cdx_api)
                if cdx_response.status_code == 200:
                    cdx_data = cdx_response.json()
                    if len(cdx_data) > 1: # Header is at index 0
                        urls = [row[0] for row in cdx_data[1:]]
                        findings.append({
                            "type": "recon",
                            "severity": Severity.RECON.value,
                            "title": "Historical URLs Discovered",
                            "description": f"Found {len(urls)} historical URLs in the Wayback Machine archive.",
                            "location": "CDX Index",
                            "category": "recon",
                            "evidence": ", ".join(urls),
                            "remediation": "Investigate historical paths for exposed backups, development files, or old endpoints.",
                            "confidence": 100,
                            "cvss": 0.0
                        })

        except Exception as e:
            logger.error(f"Wayback Machine Scan failed for {target}: {str(e)}")
            # Don't add an error finding for external API failures 
            # unless it's a critical scanner failure.

        return findings

def register(scanner_registry):
    scanner_registry.register("waybackmachine", WaybackMachineScanner)
