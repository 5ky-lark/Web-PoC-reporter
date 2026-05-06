"""
Technology Fingerprinter — Identifies server software, frameworks, and CMS.
"""

import re
import httpx
from scanners.base import BaseScanner, Finding, Severity


# Known technology signatures
TECH_SIGNATURES = {
    "headers": {
        "x-powered-by": [
            (r"PHP/?([\d.]+)?", "PHP"),
            (r"ASP\.NET", "ASP.NET"),
            (r"Express", "Express.js"),
            (r"Next\.js", "Next.js"),
        ],
        "server": [
            (r"Apache/?([\d.]+)?", "Apache"),
            (r"nginx/?([\d.]+)?", "Nginx"),
            (r"Microsoft-IIS/?([\d.]+)?", "Microsoft IIS"),
            (r"cloudflare", "Cloudflare"),
            (r"LiteSpeed", "LiteSpeed"),
        ],
        "x-aspnet-version": [(r"([\d.]+)", "ASP.NET")],
    },
    "html_patterns": [
        (r'<meta name="generator" content="WordPress ([\d.]+)"', "WordPress"),
        (r'<meta name="generator" content="Drupal', "Drupal"),
        (r'<meta name="generator" content="Joomla', "Joomla"),
        (r"/wp-content/", "WordPress"),
        (r"/wp-includes/", "WordPress"),
        (r"jquery[.-]?([\d.]+)?\.min\.js", "jQuery"),
        (r"react[.-]?([\d.]+)?\.min\.js", "React"),
        (r"vue[.-]?([\d.]+)?\.min\.js", "Vue.js"),
        (r"angular[.-]?([\d.]+)?\.min\.js", "Angular"),
        (r"bootstrap[.-]?([\d.]+)?\.min\.(js|css)", "Bootstrap"),
    ],
    "known_paths": {
        "/wp-login.php": "WordPress",
        "/wp-admin/": "WordPress",
        "/administrator/": "Joomla",
        "/user/login": "Drupal",
        "/.env": "Environment File Exposed",
        "/phpinfo.php": "PHP Info Page",
        "/server-status": "Apache Server Status",
    },
}


class TechFingerprinter(BaseScanner):
    name = "tech"
    description = "Technology Fingerprinting"

    def __init__(self):
        super().__init__()
        self.detected_tech: dict[str, str] = {}  # name -> version

    async def scan(self, target_url: str) -> list[Finding]:
        findings = []

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, verify=False) as client:
                response = await client.get(target_url)
                body = response.text
                headers = {k.lower(): v for k, v in response.headers.items()}

                # Check headers for tech signatures
                for header, patterns in TECH_SIGNATURES["headers"].items():
                    value = headers.get(header, "")
                    if value:
                        for pattern, tech_name in patterns:
                            match = re.search(pattern, value, re.IGNORECASE)
                            if match:
                                version = match.group(1) if match.lastindex else ""
                                self.detected_tech[tech_name] = version

                # Check HTML body for tech signatures
                for pattern, tech_name in TECH_SIGNATURES["html_patterns"]:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.lastindex else ""
                        self.detected_tech[tech_name] = version

                # Check known paths
                for path, tech_name in TECH_SIGNATURES["known_paths"].items():
                    try:
                        path_resp = await client.get(f"{target_url.rstrip('/')}{path}", follow_redirects=False)
                        if path_resp.status_code == 200:
                            self.detected_tech[tech_name] = ""
                            if tech_name in ("Environment File Exposed", "PHP Info Page", "Apache Server Status"):
                                findings.append(self._make_finding(
                                    title=f"Sensitive Path Exposed: {path}", severity=Severity.HIGH,
                                    cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    cwe_id="CWE-538", cwe_name="Insertion of Sensitive Information into Externally-Accessible File",
                                    description=f"The path {path} is accessible and may expose sensitive information.",
                                    evidence=f"HTTP {path_resp.status_code} at {target_url.rstrip('/')}{path}",
                                    poc_steps=[f"Navigate to {target_url.rstrip('/')}{path}", "Page returns 200 OK with content"],
                                    remediation=f"Remove or restrict access to {path} in production.",
                                ))
                    except Exception:
                        continue

            # Report detected technologies
            if self.detected_tech:
                tech_list = "\n".join(f"  - {name}" + (f" v{ver}" if ver else "") for name, ver in self.detected_tech.items())
                findings.append(self._make_finding(
                    title=f"Technologies Detected ({len(self.detected_tech)})", severity=Severity.INFO,
                    description=f"The following technologies were identified:\n{tech_list}",
                    evidence=tech_list,
                ))

                # Flag version disclosures specifically
                versioned = {n: v for n, v in self.detected_tech.items() if v and n not in ("Environment File Exposed", "PHP Info Page", "Apache Server Status")}
                if versioned:
                    findings.append(self._make_finding(
                        title="Technology Version Disclosure", severity=Severity.LOW,
                        cvss_score=2.6, cwe_id="CWE-200", cwe_name="Information Exposure",
                        description="Specific version numbers are disclosed, aiding attackers in finding known vulnerabilities.",
                        evidence="\n".join(f"{n}: {v}" for n, v in versioned.items()),
                        remediation="Hide version numbers from HTTP headers and HTML source.",
                    ))

        except Exception as e:
            findings.append(self._make_finding(
                title="Tech Fingerprint Error", severity=Severity.INFO,
                description=f"Error during technology fingerprinting: {str(e)}", evidence=str(e),
            ))
        return findings
