import asyncio
from backend.utils import get_http_client
from typing import List, Dict, Any, Optional

from Wappalyzer import Wappalyzer, WebPage

import warnings
import json
import httpx
from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import ScanInput, Severity, OwaspCategory
from backend.utils.enrichment import EnrichmentService
from backend.utils.logging_config import get_context_logger
from backend.utils import get_http_client

# Mapping from Wappalyzer categories to OSV ecosystems where possible (best-effort).
ECOSYSTEM_MAPPING = {
    "javascript-frameworks": "npm",
    "javascript-libraries": "npm",
    "web-servers": None, # e.g., Nginx, Apache - not in package managers
    "web-frameworks": None, # try tech-specific mapping below
    "programming-languages": None,
    "cms": None,
    "blogs": "npm",
    "frontend-frameworks": "npm",
    "ui-frameworks": "npm",
}

# Direct tech?ecosystem overrides for common frameworks/libraries
TECH_ECOSYSTEM_OVERRIDES = {
    # Python
    "django": "PyPI",
    "flask": "PyPI",
    "fastapi": "PyPI",
    "requests": "PyPI",
    # Ruby
    "rails": "RubyGems",
    "sinatra": "RubyGems",
    # Java
    "spring": "Maven",
    "spring boot": "Maven",
    # PHP (Packagist)
    "laravel": "Packagist",
    "symfony": "Packagist",
    # JS (npm)
    "react": "npm",
    "vue": "npm",
    "angular": "npm",
    "jquery": "npm",
}

class TechnologyFingerprintScanner(BaseScanner):
    metadata = {
        "name": "Technology Fingerprint Scanner",
        "description": "Identifies technologies and versions used by the target webapp and checks for known vulnerabilities using the OSV.dev database.",
        "owasp_category": OwaspCategory.A06_VULNERABLE_AND_OUTDATED_COMPONENTS,
        "author": "Project Echo Team",
        "version": "1.1"
    }

    def __init__(self):
        super().__init__()
        self.logger = get_context_logger(self.__class__.__name__)
        # Initialize Wappalyzer. This can be slow, so we do it once.
        # Wappalyzer.latest(update=True) is blocking, so we avoid it in an async app
        # or would run it in a thread pool on startup. For now, use cached version.
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning)
                self.wappalyzer = Wappalyzer.latest()
        except Exception as e:
            self.logger.warning(f"Failed to initialize Wappalyzer; technology analysis will be degraded: {e}")
            self.wappalyzer = None
        self._enrichment = EnrichmentService()
        self._osv_cache: Dict[str, Any] = {}

    async def scan(self, scan_input: ScanInput) -> List[Dict]:
        """
        Overrides the base scan method to perform technology fingerprinting.
        """
        try:
            return await self._perform_scan(scan_input.target, scan_input.options or {})
        except Exception as e:
            self.logger.error(f"Technology Fingerprint scan failed: {e}", exc_info=True)
            return [self._create_error_finding(f"Technology Fingerprint scan failed: {e}")]

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        """
        Performs the technology detection and vulnerability lookup.
        """
        findings = []
        try:
            async with get_http_client(verify=False, follow_redirects=True, timeout=20.0) as client:
                # Optional headless render (behind flag). Fallback to static HTML on failure.
                html_text: str = ""
                final_url: str = target
                if options.get("render_dom"):
                    try:
                        html_text, final_url = await self._render_dom_playwright(target, timeout_ms=15000)
                    except Exception:
                        # Fallback to static fetch
                        pass

                if not html_text:
                    # Fetch HTML and attempt simple heuristics for version hints in headers and meta
                    response = await client.get(target)
                    final_url = str(response.url)
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    html_text = response.text or ""
                else:
                    # When headless path used we still need headers; issue a lightweight HEAD
                    try:
                        head_resp = await client.head(final_url)
                        headers = {k.lower(): v for k, v in head_resp.headers.items()}
                    except Exception:
                        headers = {}

                webpage = WebPage(str(final_url), html_text, headers)
                technologies = {}
                if self.wappalyzer:
                    try:
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            technologies = self.wappalyzer.analyze_with_versions_and_categories(webpage)
                    except Exception as e:
                        self.logger.warning(f"Wappalyzer analysis failed; continuing with heuristics only: {e}")
                        technologies = {}
                else:
                    self.logger.info("Wappalyzer not initialized; skipping technology fingerprint analysis")

                # Heuristic extraction: meta generator, server header, powered-by
                try:
                    signatures = self._extract_signature_versions(html_text, headers)
                    # Merge signature results
                    for name, info in signatures.items():
                        entry = technologies.setdefault(name, {"versions": [], "categories": []})
                        # Merge versions
                        for v in info.get("versions", []):
                            if v not in entry["versions"]:
                                entry["versions"].append(v)
                        # Merge categories
                        for c in info.get("categories", []):
                            if c not in entry["categories"]:
                                entry["categories"].append(c)
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"Failed to analyze {target}: {e}")
            return [self._create_error_finding(f"Could not fetch or analyze the target URL: {e}")]

        if not technologies:
            return [self._create_info_finding(f"No specific technologies were identified on {target}.", target)]

        # Concurrently look up vulnerabilities for all identified technologies
        lookup_tasks = []
        for tech_name, tech_data in technologies.items():
            versions = tech_data.get("versions", [])
            categories = tech_data.get("categories", [])
            version = versions[0] if versions else None
            lookup_tasks.append(self._lookup_cves(tech_name, version, categories))
        results = await asyncio.gather(*lookup_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                for f in result:
                    try:
                        f = await self._enrichment.enrich_finding(f)
                    except Exception:
                        pass
                    findings.append(f)
            elif isinstance(result, Exception):
                self.logger.error(f"Error during CVE lookup: {result}")
                findings.append(self._create_error_finding(f"Error during CVE lookup: {result}"))

        return findings

    def _extract_signature_versions(self, html_text: str, headers: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Extract technology names and versions using static signatures.

        Returns a mapping: name -> { versions: [..], categories: [..] }
        """
        result: Dict[str, Dict[str, Any]] = {}
        try:
            import re
            # meta generator
            mg = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html_text, re.I)
            if mg:
                gen = mg.group(1)
                parts = gen.split('/')
                name = parts[0].strip().lower()
                ver = parts[-1].strip() if len(parts) > 1 else None
                result.setdefault(name, {"versions": [], "categories": ["meta"]})
                if ver and ver not in result[name]["versions"]:
                    result[name]["versions"].append(ver)

            # script src patterns: common libs with semver
            for lib, ver in re.findall(r'src=["\'][^"\']*(jquery|react|vue|angular)[^\d]*([0-9]+\.[0-9]+\.[0-9]+)[^"\']*["\']', html_text, re.I)[:10]:
                key = lib.lower()
                result.setdefault(key, {"versions": [], "categories": ["javascript-libraries"]})
                if ver not in result[key]["versions"]:
                    result[key]["versions"].append(ver)

            # Headers: Server / X-Powered-By
            server = headers.get('server') if headers else None
            powered_by = headers.get('x-powered-by') if headers else None
            if server:
                s_name, s_ver = (server.split('/') + [None])[:2]
                key = (s_name or '').lower()
                result.setdefault(key, {"versions": [], "categories": ["web-servers"]})
                if s_ver and s_ver not in result[key]["versions"]:
                    result[key]["versions"].append(s_ver)
            if powered_by:
                p_name, p_ver = (powered_by.split('/') + [None])[:2]
                key = (p_name or '').lower()
                result.setdefault(key, {"versions": [], "categories": ["x-powered-by"]})
                if p_ver and p_ver not in result[key]["versions"]:
                    result[key]["versions"].append(p_ver)
        except Exception:
            pass
        return result

    async def _render_dom_playwright(self, url: str, timeout_ms: int = 15000) -> (str, str):
        """Render DOM using Playwright if available. Returns (html, final_url)."""
        try:
            from playwright.async_api import async_playwright
        except Exception as e:
            raise RuntimeError("Playwright not installed") from e

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(url, timeout=timeout_ms, wait_until='networkidle')
            content = await page.content()
            final_url = page.url
            await context.close()
            await browser.close()
            return content, final_url

    def _map_ecosystem(self, tech_name: str, categories: List[str]) -> Optional[str]:
        name_key = (tech_name or '').lower().strip()
        if name_key in TECH_ECOSYSTEM_OVERRIDES:
            return TECH_ECOSYSTEM_OVERRIDES[name_key]
        # Category hint fallback
        for cat_name in categories:
            cat_slug = cat_name.lower().replace(' ', '-')
            eco = ECOSYSTEM_MAPPING.get(cat_slug)
            if eco:
                return eco
        return None

    async def _lookup_cves(self, tech_name: str, version: Optional[str], categories: List[str]) -> List[Dict]:
        """
        Looks up vulnerabilities for a given technology and version using the OSV.dev API.
        """
        if not version:
            return [self._create_info_finding(f"Detected technology: {tech_name} (version not identified).", f"tech:{tech_name}")]

        # Map to OSV ecosystem via overrides or categories
        ecosystem = self._map_ecosystem(tech_name, categories)

        query = {
            "version": version,
            "package": {"name": tech_name.lower()}
        }
        if ecosystem:
            query["package"]["ecosystem"] = ecosystem
        
        try:
            cache_key = f"{query['package'].get('ecosystem','')}/{query['package']['name']}@{version}"
            if cache_key in self._osv_cache:
                data = self._osv_cache[cache_key]
            else:
                async with get_http_client(timeout=10) as client:
                    resp = await client.post("https://api.osv.dev/v1/query", body=json.dumps(query))
                    if resp.status_code >= 400:
                        raise httpx.HTTPStatusError("OSV error", request=None, response=resp)
                    data = resp.json()
                # Basic in-memory cache to avoid repeated OSV hits during a run
                self._osv_cache[cache_key] = data

            if "vulns" in data and data["vulns"]:
                return [self._create_finding_from_osv(vuln, tech_name, version) for vuln in data["vulns"]]
        except httpx.HTTPStatusError as e:
            self.logger.warning(f"OSV API request failed for {tech_name} v{version}: {e.response.status_code}")
            return [self._create_error_finding(f"OSV API request failed for {tech_name} v{version}: {e.response.status_code}")]
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during CVE lookup for {tech_name}: {e}")
            return [self._create_error_finding(f"Unexpected error during CVE lookup for {tech_name}: {e}")]
        
        return []

    def _create_finding_from_osv(self, vuln_data: Dict[str, Any], tech_name: str, version: str) -> Dict:
        """
        Creates a structured finding dictionary from an OSV vulnerability object.
        """
        severity = Severity.MEDIUM # Default
        if "database_specific" in vuln_data and "severity" in vuln_data["database_specific"]:
            sev_text = vuln_data["database_specific"]["severity"].lower()
            if sev_text == "critical":
                severity = Severity.CRITICAL
            elif sev_text == "high":
                severity = Severity.HIGH
            elif sev_text == "low":
                severity = Severity.LOW

        description = vuln_data.get('summary', vuln_data.get('details'))
        if not description:
            vuln_id = vuln_data.get('id', 'N/A')
            description = (
                f"A known vulnerability with ID {vuln_id} was found in {tech_name} "
                f"version {version}. No summary was provided, but further details "
                "may be available in the references."
            )
        
        remediation = (
            f"Upgrade {tech_name} to a version that patches {vuln_data.get('id', 'this vulnerability')}. "
            "Review the vulnerability details and references for official advisories and patched versions."
        )

        return {
            "type": "vulnerability",
            "severity": severity.value,
            "title": f"Known Vulnerability in {tech_name} v{version} ({vuln_data.get('id', 'N/A')})",
            "description": description,
            "location": f"Component: {tech_name} v{version}",
            "cwe": f"OSV: {vuln_data.get('id', 'N/A')}",
            "confidence": 100,
            "category": "technology-fingerprint", # For frontend filtering
            "remediation": remediation,
            "cvss": 0, # Should be extracted from OSV data if available
            "evidence": {
                "references": [ref["url"] for ref in vuln_data.get("references", [])],
                "aliases": vuln_data.get("aliases", []),
            },
        }

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "Technology Fingerprint Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }
    
    def _create_info_finding(self, description: str, location: str) -> Dict:
        return { "type": "info", "severity": Severity.INFO.value, "title": "Technology Information", "description": description, "location": location, "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 }

def register(scanner_registry):
    scanner_registry.register("technologyfingerprint", TechnologyFingerprintScanner)
