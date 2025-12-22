import asyncio
import re
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse

from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity, OwaspCategory
from backend.utils import get_http_client

logger = logging.getLogger(__name__)

class OsintReconScanner(BaseScanner):
    """
    A scanner module for gathering OSINT (Open Source Intelligence) data from the target.
    Includes featured from WebRecon: Email harvesting, social media discovery, and more.
    """

    metadata = {
        "name": "OSINT Reconnaissance",
        "description": "Extracts intelligence like emails, social media profiles, and marketing tags.",
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
                soup = BeautifulSoup(html, 'html.parser')

                # 1. Email Harvesting
                email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                emails = set(re.findall(email_regex, html))
                for email in emails:
                    findings.append(self._create_recon_finding(
                        "Email Address Discovered",
                        f"Found email address: {email}",
                        "Email Harvesting",
                        email
                    ))

                # 2. Social Media Discovery
                social_platforms = [
                    'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com', 
                    'github.com', 'youtube.com', 't.me', 'discord.gg'
                ]
                links = [a.get('href') for a in soup.find_all('a', href=True)]
                found_social = set()
                for link in links:
                    for platform in social_platforms:
                        if platform in link:
                            if link not in found_social:
                                findings.append(self._create_recon_finding(
                                    "Social Media Profile Detected",
                                    f"Detected {platform} profile link: {link}",
                                    "Social Discovery",
                                    link
                                ))
                                found_social.add(link)

                # 3. Marketing & Analytics Tags
                tags = {
                    "Google Analytics": [r"ua-\d+-\d+", r"gtm-[a-z0-9]+"],
                    "Facebook Pixel": [r"connect\.facebook\.net"],
                    "Hotjar": [r"static\.hotjar\.com"],
                    "HubSpot": [r"js\.hs-scripts\.com"],
                    "Mailchimp": [r"chimpstatic\.com"]
                }
                for name, patterns in tags.items():
                    for pattern in patterns:
                        if re.search(pattern, html, re.I):
                            findings.append(self._create_recon_finding(
                                "Marketing/Analytics Tag Detected",
                                f"The site appears to use {name}.",
                                "Tag Discovery",
                                name
                            ))
                            break

                # 4. Public IP Addresses in Content
                ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ips = set(re.findall(ip_regex, html))
                for ip in ips:
                    # Filter out common false positives like localhost or obvious versions
                    if not (ip.startswith('127.') or ip.startswith('10.') or ip.startswith('192.168.')):
                        findings.append(self._create_recon_finding(
                            "Public IP Address Discovered",
                            f"Found public IP address in page content: {ip}",
                            "IP Discovery",
                            ip
                        ))

                # 5. HTML Comments Analysis
                comments = soup.find_all(string=lambda text: isinstance(text, Comment))
                for comment in comments:
                    if len(comment.strip()) > 10:
                        findings.append(self._create_recon_finding(
                            "HTML Comment Discovered",
                            f"Found a significant HTML comment: {comment.strip()[:150]}...",
                            "Comment Analysis",
                            comment.strip()
                        ))

        except Exception as e:
            logger.error(f"OSINT Recon Scan failed for {target}: {str(e)}")
            findings.append(self._create_error_finding(f"OSINT Recon Scan failed: {str(e)}"))

        return findings

    def _create_recon_finding(self, title: str, description: str, category_name: str, evidence: Any) -> Dict:
        """Helper to create a reconnaissance-style finding."""
        return {
            "type": "recon",
            "severity": Severity.RECON.value,
            "title": title,
            "description": description,
            "location": category_name,
            "category": "recon",
            "evidence": evidence,
            "remediation": "This is informational data gathered during reconnaissance. No immediate remediation is required unless sensitive info is exposed.",
            "confidence": 100,
            "cvss": 0.0
        }

    def _create_error_finding(self, description: str) -> Dict:
        return { 
            "type": "error", 
            "severity": Severity.INFO.value, 
            "title": "OSINT Recon Scan Error", 
            "description": description, 
            "location": "Scanner", 
            "category": "recon",
            "cwe": "N/A", 
            "remediation": "Check logs for more details.", 
            "confidence": 0, 
            "cvss": 0 
        }

def register(scanner_registry):
    scanner_registry.register("osintrecon", OsintReconScanner)
