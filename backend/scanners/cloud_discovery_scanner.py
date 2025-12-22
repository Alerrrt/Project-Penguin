import re
import logging
from typing import List, Dict, Any
from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity, OwaspCategory
from backend.utils import get_http_client

logger = logging.getLogger(__name__)

class CloudDiscoveryScanner(BaseScanner):
    """
    A scanner module for discovering references to cloud storage buckets (AWS, Azure, GCP).
    """

    metadata = {
        "name": "Cloud Storage Discovery",
        "description": "Identifies references to S3 buckets, Azure Blobs, and GCP storage in the target.",
        "owasp_category": "Informational",
        "author": "Project Echo Team",
        "version": "1.0"
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        findings: List[Dict] = []
        try:
            async with get_http_client(timeout=30) as client:
                response = await client.get(target)
                html = response.text

                # Patterns for Cloud Storage
                cloud_patterns = {
                    "Amazon S3 Bucket": r"([a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com|s3\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9.-]+)",
                    "Azure Blob Storage": r"[a-z0-9-]+\.blob\.core\.windows\.net",
                    "Google Cloud Storage": r"storage\.googleapis\.com/[a-z0-9.-]+|[a-z0-9.-]+\.storage\.googleapis\.com",
                    "DigitalOcean Spaces": r"[a-z0-9-]+\.[a-z0-9-]+\.digitaloceanspaces\.com"
                }

                for provider, pattern in cloud_patterns.items():
                    matches = set(re.findall(pattern, html, re.I))
                    for match in matches:
                        findings.append({
                            "type": "recon",
                            "severity": Severity.RECON.value,
                            "title": f"Cloud Storage Reference: {provider}",
                            "description": f"Found a reference to a {provider} bucket or storage location: {match}",
                            "location": "HTML/JS Content",
                            "category": "recon",
                            "evidence": match,
                            "remediation": "Check if the cloud storage bucket is public and whether it contains sensitive data.",
                            "confidence": 100,
                            "cvss": 0.0
                        })

        except Exception as e:
            logger.error(f"Cloud Discovery Scan failed for {target}: {str(e)}")
            findings.append(self._create_error_finding(f"Cloud Discovery Scan failed: {str(e)}"))

        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { 
            "type": "error", 
            "severity": Severity.INFO.value, 
            "title": "Cloud Discovery Scan Error", 
            "description": description, 
            "location": "Scanner", 
            "category": "recon",
            "cwe": "N/A", 
            "remediation": "Check logs.", 
            "confidence": 0, 
            "cvss": 0 
        }

def register(scanner_registry):
    scanner_registry.register("clouddiscovery", CloudDiscoveryScanner)
