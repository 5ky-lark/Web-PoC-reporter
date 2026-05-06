"""
Session Security Scanner — Checks cookie flags, session token strength, and session management.
"""

import re
import math
import httpx

from scanners.base import BaseScanner, Finding, Severity


class SessionScanner(BaseScanner):
    name = "session"
    description = "Session & Cookie Security"

    async def scan(self, target_url: str) -> list[Finding]:
        findings = []
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False) as client:
                response = await client.get(target_url)

                cookies = response.headers.get_list("set-cookie")

                if not cookies:
                    findings.append(self._make_finding(
                        title="No Cookies Set", severity=Severity.INFO,
                        description="The server does not set any cookies on the initial request.",
                    ))
                    return findings

                for cookie_header in cookies:
                    cookie_name = cookie_header.split("=")[0].strip()
                    cookie_lower = cookie_header.lower()

                    # Check Secure flag
                    if "secure" not in cookie_lower:
                        findings.append(self._make_finding(
                            title=f"Cookie '{cookie_name}' Missing Secure Flag",
                            severity=Severity.MEDIUM, cvss_score=4.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            cwe_id="CWE-614", cwe_name="Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                            description=f"The cookie '{cookie_name}' is not marked as Secure. It can be transmitted over unencrypted HTTP connections.",
                            evidence=f"Set-Cookie: {cookie_header}",
                            poc_steps=[
                                f"Inspect Set-Cookie header for '{cookie_name}'",
                                "The 'Secure' flag is absent",
                                "Cookie may be sent over HTTP, enabling interception",
                            ],
                            remediation="Add the Secure flag to all sensitive cookies.",
                        ))

                    # Check HttpOnly flag
                    if "httponly" not in cookie_lower:
                        findings.append(self._make_finding(
                            title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                            severity=Severity.MEDIUM, cvss_score=4.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                            cwe_id="CWE-1004", cwe_name="Sensitive Cookie Without 'HttpOnly' Flag",
                            description=f"The cookie '{cookie_name}' is not marked as HttpOnly. JavaScript can access it, making it vulnerable to XSS-based theft.",
                            evidence=f"Set-Cookie: {cookie_header}",
                            remediation="Add the HttpOnly flag to prevent JavaScript access to sensitive cookies.",
                        ))

                    # Check SameSite attribute
                    if "samesite" not in cookie_lower:
                        findings.append(self._make_finding(
                            title=f"Cookie '{cookie_name}' Missing SameSite Attribute",
                            severity=Severity.LOW, cvss_score=3.1,
                            cwe_id="CWE-1275", cwe_name="Sensitive Cookie with Improper SameSite Attribute",
                            description=f"The cookie '{cookie_name}' lacks a SameSite attribute. This may allow CSRF attacks.",
                            evidence=f"Set-Cookie: {cookie_header}",
                            remediation="Set SameSite=Strict or SameSite=Lax on cookies.",
                        ))
                    elif "samesite=none" in cookie_lower:
                        findings.append(self._make_finding(
                            title=f"Cookie '{cookie_name}' SameSite=None",
                            severity=Severity.LOW, cvss_score=3.1,
                            cwe_id="CWE-1275", cwe_name="Sensitive Cookie with Improper SameSite Attribute",
                            description=f"The cookie '{cookie_name}' has SameSite=None, allowing cross-site requests.",
                            evidence=f"Set-Cookie: {cookie_header}",
                            remediation="Use SameSite=Strict or Lax unless cross-site is explicitly needed.",
                        ))

                    # Check token entropy (session IDs should be random)
                    cookie_value = cookie_header.split("=", 1)[1].split(";")[0].strip() if "=" in cookie_header else ""
                    if len(cookie_value) > 8:
                        entropy = self._calculate_entropy(cookie_value)
                        if entropy < 3.0:
                            findings.append(self._make_finding(
                                title=f"Weak Session Token Entropy for '{cookie_name}'",
                                severity=Severity.HIGH, cvss_score=7.4,
                                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                cwe_id="CWE-330", cwe_name="Use of Insufficiently Random Values",
                                description=f"Cookie '{cookie_name}' has low entropy ({entropy:.1f} bits/char), suggesting a predictable session token.",
                                evidence=f"Cookie value: {cookie_value[:20]}...\nEntropy: {entropy:.2f} bits/char (recommended: >4.0)",
                                remediation="Use cryptographically secure random number generators for session tokens (e.g., secrets.token_hex(32) in Python).",
                            ))

        except Exception as e:
            findings.append(self._make_finding(
                title="Session Scan Error", severity=Severity.INFO,
                description=f"Error during session analysis: {str(e)}", evidence=str(e),
            ))
        return findings

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
