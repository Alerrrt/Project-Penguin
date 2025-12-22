import asyncio
import uuid
from typing import List, Optional, Dict, Any
import ssl
import socket
import OpenSSL.SSL
from datetime import datetime
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.logging_config import get_context_logger
import logging

from backend.scanners.base_scanner import BaseScanner
from ..config_types.models import ScanInput, Finding, Severity, OwaspCategory

logger = logging.getLogger(__name__)

class SSLTLSConfigurationAuditScanner(BaseScanner):
    """
    A scanner module for auditing SSL/TLS configurations.
    """

    metadata = {
        "name": "SSL/TLS Configuration Audit",
        "description": "Audits SSL/TLS configurations for common issues.",
        "owasp_category": "A02:2021 - Cryptographic Failures",
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
        Asynchronously connects to the target's SSL/TLS port and audits its configuration.

        Args:
            target: The target URL for the scan.
            options: Additional options for the scan.

        Returns:
            A list of findings for detected SSL/TLS configuration issues.
        """
        findings: List[Dict] = []
        target_url = target
        host = target_url.split('//')[-1].split('/')[0].split(':')[0] # Extract host from URL
        port = 443

        logger.info(f"Starting SSL/TLS Configuration Audit for {host}:{port}.")

        try:
            # Create an SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE # We want to inspect even invalid certs

            # Establish connection
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate chain
                    cert_chain = ssock.getpeercerts(binary_form=True)
                    if not cert_chain:
                        findings.append({
                            "type": "ssl_tls_missing_certificate",
                            "severity": Severity.CRITICAL,
                            "title": "Missing SSL/TLS Certificate",
                            "description": "No SSL/TLS certificate was presented by the server.",
                            "evidence": {"details": "No certificate found."},
                            "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                            "recommendation": "Install a valid SSL/TLS certificate on the server.",
                            "affected_url": target_url
                        })
                    else:
                        # Check for self-signed/expired certs (basic check)
                        for i, cert_bytes in enumerate(cert_chain):
                            cert = OpenSSL.SSL.load_certificate(OpenSSL.SSL.FILETYPE_ASN1, cert_bytes)
                            # Check expiry
                            if cert.has_expired():
                                findings.append({
                                    "type": "ssl_tls_expired_certificate",
                                    "severity": Severity.HIGH,
                                    "title": "Expired SSL/TLS Certificate",
                                    "description": f"SSL/TLS certificate in chain (index {i}) has expired.",
                                    "evidence": {"details": f"Certificate expired on {cert.get_notAfter().decode()}"},
                                    "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                    "recommendation": "Renew the expired SSL/TLS certificate.",
                                    "affected_url": target_url
                                })
                            # Check if self-signed (simplistic: issuer == subject and not in a common CA list)
                            if cert.get_subject().get_components() == cert.get_issuer().get_components() and i == 0:
                                findings.append({
                                    "type": "ssl_tls_self_signed_certificate",
                                    "severity": Severity.MEDIUM,
                                    "title": "Self-Signed SSL/TLS Certificate",
                                    "description": "The server is using a self-signed SSL/TLS certificate, which is not trusted by default browsers.",
                                    "evidence": {"details": "Issuer and Subject are identical (self-signed)."},
                                    "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                    "recommendation": "Obtain and install a certificate from a trusted Certificate Authority (CA).",
                                    "affected_url": target_url
                                })

                    # Check for weak ciphers (requires more detailed logic with ssl.get_ciphers() and known weak lists)
                    try:
                        current_cipher = ssock.cipher()
                        if current_cipher and ("RC4" in current_cipher[0] or "3DES" in current_cipher[0]):
                            findings.append({
                                "type": "ssl_tls_weak_cipher",
                                "severity": Severity.HIGH,
                                "title": "Weak SSL/TLS Cipher Used",
                                "description": f"The server is using a weak SSL/TLS cipher suite: {current_cipher[0]}.",
                                "evidence": {"details": f"Weak cipher: {current_cipher[0]} detected."},
                                "owasp_category": OwaspCategory.CRYPTOGRAPHIC_FAILURES,
                                "recommendation": "Configure the web server to use strong, modern cipher suites only.",
                                "affected_url": target_url
                            })
                    except Exception as e:
                        logger.warning(f"Could not retrieve current cipher: {e}")

        except (socket.error, ssl.SSLError) as e:
            findings.append({
                "type": "ssl_tls_connection_error",
                "severity": Severity.HIGH if isinstance(e, ssl.SSLError) else Severity.MEDIUM,
                "title": "SSL/TLS Connection Error",
                "description": f"Could not establish SSL/TLS connection to {host}:{port}: {e}. This might indicate an issue with SSL/TLS setup or an unreachable host.",
                "evidence": {"details": str(e)},
                "owasp_category": OwaspCategory.SECURITY_MISCONFIGURATION,
                "recommendation": "Ensure SSL/TLS is properly configured on the server and the port is open.",
                "affected_url": target_url
            })
        except Exception as e:
            logger.error(f"An unexpected error occurred during SSL/TLS audit of {host}:{port}", extra={"error": str(e)})

        logger.info(f"Finished SSL/TLS Configuration Audit for {host}:{port}.")
        return findings

    def _create_error_finding(self, description: str) -> Dict:
        return { "type": "error", "severity": Severity.INFO, "title": "SSL/TLS Configuration Audit Error", "description": description, "location": "Scanner", "cwe": "N/A", "remediation": "N/A", "confidence": 0, "cvss": 0 } 
