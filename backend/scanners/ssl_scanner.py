"""
SSL/TLS Scanner — Assesses SSL/TLS configuration and certificate health.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from scanners.base import BaseScanner, Finding, Severity


class SSLScanner(BaseScanner):
    name = "ssl"
    description = "SSL/TLS Configuration Analysis"

    async def scan(self, target_url: str) -> list[Finding]:
        findings = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            findings.append(self._make_finding(
                title="Site Not Using HTTPS", severity=Severity.HIGH,
                cvss_score=7.4, cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-319", cwe_name="Cleartext Transmission of Sensitive Information",
                description="The target is served over HTTP, not HTTPS. All traffic is unencrypted.",
                evidence=f"URL scheme: {parsed.scheme}",
                poc_steps=[f"Navigate to {target_url}", "Observe HTTP (not HTTPS) in URL"],
                remediation="Enable HTTPS with a valid TLS certificate. Use Let's Encrypt for free certificates.",
            ))
            return findings

        try:
            # Check certificate details
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()

            # Certificate expiration
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (not_after - datetime.now(timezone.utc)).days

            if days_left <= 0:
                findings.append(self._make_finding(
                    title="SSL Certificate Expired", severity=Severity.CRITICAL,
                    cvss_score=9.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-295", cwe_name="Improper Certificate Validation",
                    description=f"The SSL certificate expired on {not_after.strftime('%Y-%m-%d')}.",
                    evidence=f"Certificate notAfter: {cert['notAfter']}",
                    poc_steps=["Connect to the target via HTTPS", "Inspect certificate", "Certificate is expired"],
                    remediation="Renew the SSL certificate immediately.",
                ))
            elif days_left <= 30:
                findings.append(self._make_finding(
                    title="SSL Certificate Expiring Soon", severity=Severity.MEDIUM,
                    cvss_score=4.3, cwe_id="CWE-295", cwe_name="Improper Certificate Validation",
                    description=f"Certificate expires in {days_left} days ({not_after.strftime('%Y-%m-%d')}).",
                    evidence=f"Days until expiration: {days_left}",
                    remediation="Renew the SSL certificate before expiration.",
                ))

            # Protocol version check
            if protocol and protocol in ("TLSv1", "TLSv1.1"):
                findings.append(self._make_finding(
                    title=f"Outdated TLS Protocol ({protocol})", severity=Severity.HIGH,
                    cvss_score=7.4, cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-326", cwe_name="Inadequate Encryption Strength",
                    description=f"Server supports {protocol} which has known vulnerabilities.",
                    evidence=f"Negotiated protocol: {protocol}",
                    remediation="Disable TLS 1.0 and 1.1. Enable only TLS 1.2 and 1.3.",
                ))

            # Cipher strength
            if cipher and cipher[2] and cipher[2] < 128:
                findings.append(self._make_finding(
                    title="Weak Cipher Suite", severity=Severity.HIGH,
                    cvss_score=7.4, cwe_id="CWE-326", cwe_name="Inadequate Encryption Strength",
                    description=f"Cipher {cipher[0]} uses only {cipher[2]}-bit encryption.",
                    evidence=f"Cipher: {cipher[0]}, Bits: {cipher[2]}",
                    remediation="Configure the server to use 128-bit or higher cipher suites.",
                ))

            if not findings:
                findings.append(self._make_finding(
                    title="SSL/TLS Configuration Secure", severity=Severity.INFO,
                    description=f"Certificate valid for {days_left} days. Protocol: {protocol}. Cipher: {cipher[0] if cipher else 'N/A'}.",
                    evidence=f"Protocol: {protocol}, Cipher: {cipher}, Expires: {not_after}",
                ))

        except ssl.SSLCertVerificationError as e:
            findings.append(self._make_finding(
                title="SSL Certificate Verification Failed", severity=Severity.HIGH,
                cvss_score=7.4, cwe_id="CWE-295", cwe_name="Improper Certificate Validation",
                description=f"Certificate verification failed: {str(e)}",
                evidence=str(e), remediation="Ensure a valid, trusted SSL certificate is installed.",
            ))
        except Exception as e:
            findings.append(self._make_finding(
                title="SSL/TLS Scan Error", severity=Severity.INFO,
                description=f"Error during SSL/TLS analysis: {str(e)}", evidence=str(e),
            ))
        return findings
