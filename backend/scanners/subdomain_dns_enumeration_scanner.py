import asyncio
import uuid
import logging
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from datetime import datetime

import dns.resolver
import dns.exception
try:
    import whois
except ImportError:
    whois = None

from backend.utils import get_http_client
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
from backend.scanners.base_scanner import BaseScanner
from ..config_types.models import ScanInput, Finding, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class SubdomainDNSEnumerationScanner(BaseScanner):
    """
    A scanner module for discovering subdomains and gathering DNS/WHOIS intelligence.
    """

    metadata = {
        "name": "Subdomain & DNS Intelligence",
        "description": "Discovers subdomains and gathers MX, TXT, NS records and WHOIS information.",
        "owasp_category": "Informational",
        "author": "Project Echo Team",
        "version": "1.1"
    }

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="subdomain_dns_enum_scanner")
    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        start_time = datetime.now()
        scan_id = f"{self.__class__.__name__}_{start_time.strftime('%Y%m%d_%H%M%S')}"
        try:
            results = await self._perform_scan(scan_input.target, scan_input.options or {})
            self._update_metrics(True, start_time)
            return results
        except Exception as e:
            self._update_metrics(False, start_time)
            logger.error(f"Scan failed: {e}", exc_info=True)
            raise

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        findings: List[Dict] = []
        parsed_url = urlparse(target)
        domain = parsed_url.netloc or parsed_url.path.strip('/')
        
        if not domain:
            return findings

        # 1. Gather WHOIS Information
        await self._gather_whois(domain, findings)

        # 2. Gather DNS Records (MX, TXT, NS)
        await self._gather_dns_records(domain, findings)

        # 3. Subdomain Enumeration
        subdomains_wordlist = options.get('wordlist', [
            "www", "mail", "api", "dev", "test", "admin", "blog",
            "shop", "cdn", "beta", "staging", "webmail", "ftp"
        ])

        tasks = [self._check_subdomain(f"{sub}.{domain}", target) for sub in subdomains_wordlist]
        subdomain_results = await asyncio.gather(*tasks)
        for result in subdomain_results:
            if result:
                findings.append(result)

        return findings

    async def _gather_whois(self, domain: str, findings: List[Dict]):
        if not whois:
            return
        try:
            # whois.whois is a blocking call, wrap in thread
            w = await asyncio.to_thread(whois.whois, domain)
            if w:
                findings.append({
                    "type": "recon",
                    "severity": Severity.RECON.value,
                    "title": "WHOIS Records Discovered",
                    "description": f"Gathered WHOIS information for {domain}.",
                    "location": "WHOIS Lookup",
                    "category": "recon",
                    "evidence": {
                        "registrar": w.registrar,
                        "creation_date": str(w.creation_date),
                        "expiration_date": str(w.expiration_date),
                        "emails": w.emails,
                        "org": w.org
                    },
                    "remediation": "Review domain registration for sensitive information disclosure.",
                    "confidence": 100,
                    "cvss": 0.0
                })
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")

    async def _gather_dns_records(self, domain: str, findings: List[Dict]):
        record_types = ['MX', 'TXT', 'NS', 'A']
        for rtype in record_types:
            try:
                answers = await asyncio.to_thread(dns.resolver.resolve, domain, rtype)
                records = [str(rdata) for rdata in answers]
                if records:
                    findings.append({
                        "type": "recon",
                        "severity": Severity.RECON.value,
                        "title": f"DNS {rtype} Records Discovered",
                        "description": f"Found {len(records)} {rtype} records for {domain}.",
                        "location": "DNS Lookup",
                        "category": "recon",
                        "evidence": records,
                        "remediation": "Review DNS records for misconfigurations or unintended information exposure (e.g., in TXT records).",
                        "confidence": 100,
                        "cvss": 0.0
                    })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            except Exception as e:
                logger.warning(f"DNS {rtype} lookup failed for {domain}: {e}")

    async def _check_subdomain(self, subdomain: str, base_url: str) -> Optional[Dict]:
        try:
            answers = await asyncio.to_thread(dns.resolver.resolve, subdomain, 'A')
            ip_address = str(answers[0])

            try:
                async with get_http_client(follow_redirects=True, timeout=5) as client:
                    scheme = urlparse(base_url).scheme or 'http'
                    subdomain_url = f"{scheme}://{subdomain}"
                    response = await client.get(subdomain_url)
                    if response.status_code < 500:
                        return {
                            "type": "recon", # Changed to recon
                            "severity": Severity.RECON.value,
                            "title": "Subdomain Discovered",
                            "description": f"Active subdomain '{subdomain}' resolved to IP '{ip_address}' and returned HTTP status '{response.status_code}'.",
                            "evidence": {
                                "subdomain": subdomain,
                                "resolved_ip": ip_address,
                                "http_status": response.status_code
                            },
                            "category": "recon",
                            "remediation": "Review this subdomain for intended public availability.",
                            "affected_url": subdomain_url,
                            "confidence": 100,
                            "cvss": 0.0
                        }
            except Exception:
                return {
                    "type": "recon",
                    "severity": Severity.RECON.value,
                    "title": "Subdomain Discovered (HTTP Unreachable)",
                    "description": f"Active subdomain '{subdomain}' resolved to IP '{ip_address}' but was unreachable via HTTP.",
                    "evidence": {
                        "subdomain": subdomain,
                        "resolved_ip": ip_address
                    },
                    "category": "recon",
                    "remediation": "Investigate internal network exposure.",
                    "affected_url": f"http://{subdomain}",
                    "confidence": 80,
                    "cvss": 0.0
                }

        except Exception:
            pass
        return None
