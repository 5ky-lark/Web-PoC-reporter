"""
CVE Lookup — Matches detected software versions against known CVEs.
"""

from scanners.base import BaseScanner, Finding, Severity

# Built-in database of critical CVEs for common software
KNOWN_CVES = {
    "Apache": [
        {"version_below": "2.4.58", "cve": "CVE-2023-43622", "cvss": 7.5, "title": "Apache HTTP Server DoS via HTTP/2", "desc": "Denial of service via HTTP/2 CONTINUATION frames."},
        {"version_below": "2.4.56", "cve": "CVE-2023-25690", "cvss": 9.8, "title": "Apache HTTP Request Smuggling", "desc": "HTTP request smuggling via mod_rewrite and mod_proxy."},
    ],
    "Nginx": [
        {"version_below": "1.25.4", "cve": "CVE-2024-24989", "cvss": 7.5, "title": "Nginx HTTP/3 NULL Pointer", "desc": "NULL pointer dereference in HTTP/3 QUIC module."},
    ],
    "WordPress": [
        {"version_below": "6.4.3", "cve": "CVE-2024-31210", "cvss": 8.8, "title": "WordPress Remote Code Execution", "desc": "RCE via malicious plugin upload on Windows servers."},
        {"version_below": "6.3.2", "cve": "CVE-2023-39999", "cvss": 6.5, "title": "WordPress Sensitive Information Exposure", "desc": "Contributor+ can access post content via REST API."},
    ],
    "jQuery": [
        {"version_below": "3.5.0", "cve": "CVE-2020-11022", "cvss": 6.1, "title": "jQuery XSS via HTML Manipulation", "desc": "XSS when passing malicious HTML to jQuery DOM manipulation methods."},
    ],
    "PHP": [
        {"version_below": "8.2.18", "cve": "CVE-2024-4577", "cvss": 9.8, "title": "PHP CGI Argument Injection", "desc": "Critical argument injection in PHP-CGI on Windows."},
        {"version_below": "8.1.28", "cve": "CVE-2024-2756", "cvss": 6.5, "title": "PHP Cookie Bypass", "desc": "Security cookie bypass via __Host-/__Secure- prefix."},
    ],
    "Microsoft IIS": [
        {"version_below": "10.1", "cve": "CVE-2023-36899", "cvss": 7.5, "title": "IIS ASP.NET Elevation of Privilege", "desc": "Elevation of privilege in ASP.NET on IIS."},
    ],
    "Express.js": [
        {"version_below": "4.19.2", "cve": "CVE-2024-29041", "cvss": 6.1, "title": "Express.js Open Redirect", "desc": "Open redirect via malformed URLs in res.redirect()."},
    ],
    "Bootstrap": [
        {"version_below": "4.3.1", "cve": "CVE-2019-8331", "cvss": 6.1, "title": "Bootstrap XSS in Tooltip/Popover", "desc": "XSS via data-template attribute in tooltip and popover plugins."},
    ],
}


def _version_compare(current: str, threshold: str) -> bool:
    """Return True if current version is below threshold."""
    try:
        curr_parts = [int(x) for x in current.split(".")]
        thresh_parts = [int(x) for x in threshold.split(".")]
        # Pad shorter list
        max_len = max(len(curr_parts), len(thresh_parts))
        curr_parts.extend([0] * (max_len - len(curr_parts)))
        thresh_parts.extend([0] * (max_len - len(thresh_parts)))
        return curr_parts < thresh_parts
    except (ValueError, AttributeError):
        return False


class CVELookup(BaseScanner):
    name = "cve"
    description = "CVE Vulnerability Lookup"

    def __init__(self):
        super().__init__()
        self.detected_technologies: dict[str, str] = {}

    async def scan(self, target_url: str) -> list[Finding]:
        findings = []

        if not self.detected_technologies:
            findings.append(self._make_finding(
                title="No Technologies for CVE Lookup", severity=Severity.INFO,
                description="No detected technologies with version numbers to match against CVE database.",
            ))
            return findings

        for tech_name, version in self.detected_technologies.items():
            if not version or tech_name in ("Environment File Exposed", "PHP Info Page", "Apache Server Status"):
                continue

            cve_entries = KNOWN_CVES.get(tech_name, [])
            for entry in cve_entries:
                if _version_compare(version, entry["version_below"]):
                    from scanners.base import severity_from_cvss
                    findings.append(self._make_finding(
                        title=f"{entry['title']} ({entry['cve']})",
                        severity=severity_from_cvss(entry["cvss"]),
                        cvss_score=entry["cvss"],
                        cwe_id=entry["cve"],
                        description=f"{entry['desc']}\n\nDetected: {tech_name} {version}\nAffects versions below: {entry['version_below']}",
                        evidence=f"Technology: {tech_name}\nVersion: {version}\nCVE: {entry['cve']}\nCVSS: {entry['cvss']}",
                        poc_steps=[
                            f"Identified {tech_name} version {version}",
                            f"This version is affected by {entry['cve']}",
                            f"Upgrade to {tech_name} {entry['version_below']} or later",
                        ],
                        remediation=f"Upgrade {tech_name} to version {entry['version_below']} or later to patch {entry['cve']}.",
                        references=[f"https://nvd.nist.gov/vuln/detail/{entry['cve']}"],
                    ))

        if not findings:
            findings.append(self._make_finding(
                title="No Known CVEs Matched", severity=Severity.INFO,
                description="No known CVEs matched the detected technology versions.",
                evidence="\n".join(f"{k}: {v}" for k, v in self.detected_technologies.items() if v),
            ))
        return findings
