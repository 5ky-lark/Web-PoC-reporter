"""
Clickjacking Scanner — Checks for clickjacking protection mechanisms.
"""

import httpx
from scanners.base import BaseScanner, Finding, Severity


class ClickjackScanner(BaseScanner):
    name = "clickjack"
    description = "Clickjacking Protection Check"

    async def scan(self, target_url: str) -> list[Finding]:
        findings = []
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, verify=False) as client:
                response = await client.get(target_url)
                headers = {k.lower(): v for k, v in response.headers.items()}
                body = response.text

                has_xfo = "x-frame-options" in headers
                xfo_value = headers.get("x-frame-options", "").upper()

                # Check CSP frame-ancestors
                csp = headers.get("content-security-policy", "")
                has_frame_ancestors = "frame-ancestors" in csp.lower()

                # Check for JS frame-busting
                js_framebusters = [
                    "top.location", "top.location.href", "window.top",
                    "self !== top", "self != top", "top !== self",
                    "parent.frames.length", "top.location.replace",
                ]
                has_js_buster = any(fb in body for fb in js_framebusters)

                if not has_xfo and not has_frame_ancestors:
                    if has_js_buster:
                        findings.append(self._make_finding(
                            title="Clickjacking Protection (JS Only — Weak)",
                            severity=Severity.LOW, cvss_score=3.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
                            cwe_id="CWE-1021", cwe_name="Improper Restriction of Rendered UI Layers",
                            description="Page relies only on JavaScript frame-busting which can be bypassed.",
                            evidence="No X-Frame-Options or CSP frame-ancestors header.\nJavaScript frame-busting code detected in page source.",
                            poc_steps=[
                                f"Inspect headers of {target_url}",
                                "No X-Frame-Options or CSP frame-ancestors found",
                                "Only JavaScript-based protection detected (bypassable)",
                            ],
                            remediation="Add X-Frame-Options: DENY and CSP frame-ancestors 'none' headers.",
                            references=["https://owasp.org/www-community/attacks/Clickjacking"],
                        ))
                    else:
                        findings.append(self._make_finding(
                            title="No Clickjacking Protection",
                            severity=Severity.MEDIUM, cvss_score=4.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                            cwe_id="CWE-1021", cwe_name="Improper Restriction of Rendered UI Layers",
                            description="The page has no clickjacking protection. It can be embedded in a malicious iframe to trick users into performing unintended actions.",
                            evidence=f"X-Frame-Options: Not set\nCSP frame-ancestors: Not set\nJS frame-busting: Not detected",
                            poc_steps=[
                                f"Create an HTML page with: <iframe src='{target_url}'></iframe>",
                                "Open the HTML page in a browser",
                                "The target page renders inside the iframe",
                                "An attacker can overlay invisible elements to hijack clicks",
                            ],
                            remediation="Add X-Frame-Options: DENY header and CSP with frame-ancestors 'none'.",
                            references=["https://owasp.org/www-community/attacks/Clickjacking"],
                        ))
                else:
                    details = []
                    if has_xfo:
                        details.append(f"X-Frame-Options: {xfo_value}")
                    if has_frame_ancestors:
                        details.append(f"CSP frame-ancestors present")
                    findings.append(self._make_finding(
                        title="Clickjacking Protection Present", severity=Severity.INFO,
                        description="Clickjacking protections are properly configured.",
                        evidence="\n".join(details),
                    ))

        except Exception as e:
            findings.append(self._make_finding(
                title="Clickjacking Scan Error", severity=Severity.INFO,
                description=f"Error during clickjacking check: {str(e)}", evidence=str(e),
            ))
        return findings
