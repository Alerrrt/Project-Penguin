import httpx
from typing import Dict, List
from datetime import datetime

from backend.scanners.base_scanner import BaseScanner
from backend.config_types.models import Severity
from backend.utils import get_http_client
from backend.utils.crawler import seed_urls
import re


class CorsMisconfigurationScanner(BaseScanner):
    metadata = {
        "name": "CORS Misconfiguration Scanner",
        "description": "Detects common CORS misconfigurations like wildcard origins with credentials and reflective origins.",
        "owasp_category": "Security Misconfiguration",
        "author": "Project Echo",
        "version": "1.0.0",
    }

    async def _perform_scan(self, target: str, options: Dict) -> List[Dict]:
        findings: List[Dict] = []

        test_origin = options.get("test_origin", "https://evil.example")
        timeout = float(options.get("timeout", 15))
        max_urls = int(options.get("max_urls", 8))
        include_seeds = bool(options.get("use_seeds", True))

        urls_to_check = [target]
        addl_paths = options.get("paths", ["/", "/api", "/health"])  # heuristic

        # Normalize target to include scheme
        def with_scheme(u: str) -> str:
            if u.startswith("http://") or u.startswith("https://"):
                return u
            return f"https://{u}"

        base = with_scheme(target)
        for p in addl_paths:
            if not p.startswith("/"):
                p = f"/{p}"
            urls_to_check.append(base.rstrip("/") + p)

        # Optionally augment with mini-crawler seeds
        if include_seeds:
            try:
                seeds = await seed_urls(base, max_urls=max_urls)
                urls_to_check = list(dict.fromkeys(urls_to_check + seeds))
            except Exception:
                pass

        async with get_http_client(timeout=timeout) as session:
            for url in urls_to_check:
                try:
                    resp = await session.get(url, headers={"Origin": test_origin})
                    acao = resp.headers.get("Access-Control-Allow-Origin")
                    acac = resp.headers.get("Access-Control-Allow-Credentials")
                    acam = resp.headers.get("Access-Control-Allow-Methods")
                    acrh = resp.headers.get("Access-Control-Allow-Headers")
                    vary = resp.headers.get("Vary")

                    # High: wildcard with credentials
                    if acao == "*" and (acac or "").lower() == "true":
                        f = self._finding(
                            severity=Severity.HIGH,
                            title="CORS allows any origin with credentials",
                            description="Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true. This allows credentialed requests from any origin.",
                            location=url,
                            remediation="Do not combine '*' with credentials. Set ACAO to a specific trusted origin and review credential usage.",
                            evidence={"headers": dict(resp.headers)}
                        )
                        self._enrich_with_cwe_cve(f)
                        findings.append(f)

                    # High: reflective origin with credentials
                    if acao and acao == test_origin and (acac or "").lower() == "true":
                        f = self._finding(
                            severity=Severity.HIGH,
                            title="CORS reflects arbitrary Origin with credentials",
                            description="The server reflects the request Origin in ACAO and also allows credentials, enabling cross-origin credential theft.",
                            location=url,
                            remediation="Whitelist specific trusted origins and avoid credentials unless strictly required.",
                            evidence={"headers": dict(resp.headers), "origin": test_origin}
                        )
                        self._enrich_with_cwe_cve(f)
                        findings.append(f)

                    # Medium: overly permissive methods/headers
                    if acam and ("*" in acam or "DELETE" in acam or "PUT" in acam):
                        f = self._finding(
                            severity=Severity.MEDIUM,
                            title="CORS allows overly permissive methods",
                            description="Allowed methods include '*' or powerful methods like DELETE/PUT.",
                            location=url,
                            remediation="Limit allowed methods to those strictly needed (e.g., GET, POST).",
                            evidence={"methods": acam}
                        )
                        self._enrich_with_cwe_cve(f)
                        findings.append(f)

                    if acrh and ("*" in acrh or "authorization" in acrh.lower()):
                        f = self._finding(
                            severity=Severity.MEDIUM,
                            title="CORS allows overly permissive headers",
                            description="Allowed headers include '*' or sensitive headers like Authorization.",
                            location=url,
                            remediation="Limit allowed headers to a minimal, explicit list. Avoid exposing Authorization unless necessary.",
                            evidence={"headers": acrh}
                        )
                        self._enrich_with_cwe_cve(f)
                        findings.append(f)

                    # Low: missing Vary: Origin for dynamic ACAO
                        if acao and acao != "*" and (not vary or "origin" not in vary.lower()):
                            f = self._finding(
                                severity=Severity.LOW,
                                title="CORS reflects origin without Vary: Origin",
                                description="Dynamic ACAO without Vary: Origin may cause caching issues and leak cross-origin responses.",
                                location=url,
                                remediation="Add 'Vary: Origin' when ACAO varies based on request origin.",
                                evidence={"acao": acao, "vary": vary}
                            )
                            self._enrich_with_cwe_cve(f)
                            findings.append(f)

                        # Preflight check (OPTIONS) for typical custom header
                        try:
                            pre = await session.request(
                                "OPTIONS",
                                url,
                                headers={
                                    "Origin": test_origin,
                                    "Access-Control-Request-Method": "POST",
                                    "Access-Control-Request-Headers": "Authorization, X-Test-Header",
                                },
                            )
                            pre_acam = pre.headers.get("Access-Control-Allow-Methods", "")
                            pre_acrh = pre.headers.get("Access-Control-Allow-Headers", "")
                            if "*" in pre_acam or any(m in (pre_acam or "") for m in ["DELETE", "PUT"]):
                                f = self._finding(
                                    severity=Severity.MEDIUM,
                                    title="Preflight allows overly permissive methods",
                                    description="Preflight response permits '*' or powerful methods like DELETE/PUT.",
                                    location=url,
                                    remediation="Restrict methods in preflight responses to exactly those required.",
                                    evidence={"preflight_methods": pre_acam},
                                )
                                findings.append(f)
                            if "*" in pre_acrh or "authorization" in pre_acrh.lower():
                                f = self._finding(
                                    severity=Severity.MEDIUM,
                                    title="Preflight allows overly permissive headers",
                                    description="Preflight response allows '*' or sensitive headers like Authorization.",
                                    location=url,
                                    remediation="Do not allow wildcard headers; explicitly enumerate safe headers.",
                                    evidence={"preflight_headers": pre_acrh},
                                )
                                findings.append(f)
                        except Exception:
                            pass

                except Exception as e:
                    # Non-fatal; record as info
                    findings.append(self._finding(
                        severity=Severity.INFO,
                        title="CORS check error",
                        description=str(e),
                        location=url,
                        remediation="Ensure the target is reachable and supports HTTP(S).",
                        evidence={}
                    ))

        return findings

    def _finding(self, severity: Severity, title: str, description: str, location: str, remediation: str, evidence: Dict) -> Dict:
        return {
            "type": "cors",
            "severity": severity,
            "title": title,
            "description": description,
            "location": location,
            "cwe": "CWE-942",
            "remediation": remediation,
            "confidence": 80,
            "cvss": 0,
            "evidence": evidence,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _enrich_with_cwe_cve(self, f: Dict) -> None:
        """Lightweight enrichment mapping specific CORS patterns to CWE/CVE hints."""
        title = f.get("title", "").lower()
        desc = f.get("description", "").lower()
        # CWE mapping already set to CWE-942; refine confidence
        if "credentials" in desc and ("*" in desc or "any origin" in desc):
            f["confidence"] = 90
            f["cvss"] = max(f.get("cvss", 0), 7.5)
        if "authorization" in desc:
            f["confidence"] = max(f.get("confidence", 80), 85)
        # Known CVEs around lax CORS exist for specific products; we can hint generically
        product_header = str(f.get("evidence", {}).get("headers", {})).lower()
        matches = re.findall(r"server['\"]?:\s*([^,}]+)", product_header)
        if matches:
            # generic hint tying to CVE searchability
            f["cve"] = "Potential CVEs related to product CORS; validate against vendor advisories"

