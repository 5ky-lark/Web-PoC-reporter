"""HTTP security-headers scanner with raw HTTP capture."""

import httpx

import cvss
from scanners.base import BaseScanner, Finding, Confidence


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "vector_name": "missing_csp",
        "cwe_id": "CWE-693", "cwe_name": "Protection Mechanism Failure",
        "description": (
            "Content-Security-Policy is missing. CSP is the strongest mitigation against "
            "XSS / injection. Without it, any reflected or stored XSS executes unimpeded."
        ),
        "remediation": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
    },
    "Strict-Transport-Security": {
        "vector_name": "missing_hsts",
        "cwe_id": "CWE-319", "cwe_name": "Cleartext Transmission of Sensitive Information",
        "description": (
            "HSTS is missing. Users who type the bare hostname or follow an HTTP link "
            "may transit credentials in cleartext until the upgrade-to-HTTPS redirect."
        ),
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    },
    "X-Frame-Options": {
        "vector_name": "missing_xfo",
        "cwe_id": "CWE-1021", "cwe_name": "Improper Restriction of Rendered UI Layers",
        "description": "X-Frame-Options header missing. The page can be embedded in malicious iframes (clickjacking).",
        "remediation": "Add: X-Frame-Options: DENY (or use CSP frame-ancestors).",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
    },
    "X-Content-Type-Options": {
        "vector_name": "missing_xcto",
        "cwe_id": "CWE-16", "cwe_name": "Configuration",
        "description": "X-Content-Type-Options header missing. Browsers may sniff MIME types and execute uploaded content as scripts.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    },
    "Referrer-Policy": {
        "vector_name": "missing_referrer",
        "cwe_id": "CWE-200", "cwe_name": "Information Exposure",
        "description": "Referrer-Policy missing. Full URLs (with tokens or session info in path) may leak to third-party sites.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
    },
    "Permissions-Policy": {
        "vector_name": "missing_permissions",
        "cwe_id": "CWE-693", "cwe_name": "Protection Mechanism Failure",
        "description": "Permissions-Policy missing. Browser features (camera, mic, geo) are not restricted by default policy.",
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
    },
}


class HeaderScanner(BaseScanner):
    name = "headers"
    description = "HTTP security headers analysis"

    async def scan(self, target_url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(
                timeout=15.0, follow_redirects=True, verify=False
            ) as client:
                resp, capture = await self.request(client, "GET", target_url)
                if resp is None:
                    return findings
                headers_lc = {k.lower(): v for k, v in resp.headers.items()}

                for header_name, meta in SECURITY_HEADERS.items():
                    self.cancel_token.raise_if_cancelled()
                    if header_name.lower() not in headers_lc:
                        findings.append(self._make_finding(
                            title=f"Missing {header_name}",
                            cvss_vector=cvss.vector(meta["vector_name"]),
                            cwe_id=meta["cwe_id"],
                            cwe_name=meta["cwe_name"],
                            description=meta["description"],
                            evidence=f"Response headers: {', '.join(resp.headers.keys())}",
                            capture=capture,
                            poc_steps=[
                                f"GET {target_url}",
                                f"Inspect response headers — {header_name} is absent",
                            ],
                            remediation=meta["remediation"],
                            references=meta["references"],
                            target_url=target_url,
                            confidence=Confidence.EXECUTED,
                        ))

                server = headers_lc.get("server", "")
                if server and any(c in server.lower() for c in ["/", ".", "apache", "nginx", "iis"]):
                    findings.append(self._make_finding(
                        title="Server version disclosed in Server header",
                        cvss_vector=cvss.vector("info_disclosure"),
                        cwe_id="CWE-200",
                        cwe_name="Information Exposure",
                        description=f"Server header reveals: {server!r}. Reveals version-specific CVE surface to attackers.",
                        evidence=f"Server: {server}",
                        capture=capture,
                        remediation="Apache: ServerTokens Prod. Nginx: server_tokens off.",
                        target_url=target_url,
                        confidence=Confidence.EXECUTED,
                    ))

                powered_by = headers_lc.get("x-powered-by", "")
                if powered_by:
                    findings.append(self._make_finding(
                        title="X-Powered-By information disclosure",
                        cvss_vector=cvss.vector("info_disclosure"),
                        cwe_id="CWE-200",
                        cwe_name="Information Exposure",
                        description=f"X-Powered-By reveals: {powered_by!r}",
                        evidence=f"X-Powered-By: {powered_by}",
                        capture=capture,
                        remediation="Strip the X-Powered-By header at the reverse proxy.",
                        target_url=target_url,
                        confidence=Confidence.EXECUTED,
                    ))

        except Exception as e:
            findings.append(self._make_finding(
                title="Header scan error",
                description=str(e),
            ))
        return findings
