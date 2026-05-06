"""
Access Control Scanner — Detects exposed admin panels and sensitive endpoints.
"""
import httpx
from scanners.base import BaseScanner, Finding, Severity

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin/login", "/admin/dashboard",
    "/wp-admin", "/wp-login.php", "/manager", "/cpanel", "/panel",
    "/dashboard", "/console", "/backend", "/admin-panel",
    "/api/admin", "/api/admin/users", "/api/admin/settings",
    "/api/users", "/api/users/all", "/api/accounts",
    "/phpmyadmin", "/adminer", "/adminer.php",
    "/actuator", "/actuator/health", "/actuator/env",
    "/server-status", "/server-info", "/.env",
    "/info.php", "/phpinfo.php", "/.git/HEAD", "/.git/config",
]

SENSITIVE_SIGS = {
    "/.env": ["DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY"],
    "/.git/HEAD": ["ref: refs/heads/"],
    "/phpinfo.php": ["phpinfo()", "PHP Version"],
    "/info.php": ["phpinfo()", "PHP Version"],
}

USER_DATA_PATHS = [
    "/api/user/1", "/api/user/2", "/api/users/1", "/api/users/2",
    "/api/profile/1", "/api/account/1", "/api/orders/1",
]


class AccessControlScanner(BaseScanner):
    name = "accesscontrol"
    description = "Access Control & Admin Exposure"

    async def scan(self, target_url: str) -> list[Finding]:
        findings = []
        base = target_url.rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
                for path in ADMIN_PATHS:
                    url = base + path
                    try:
                        resp = await client.get(url, timeout=5.0)
                        if path in SENSITIVE_SIGS:
                            body = resp.text.lower()
                            for sig in SENSITIVE_SIGS[path]:
                                if sig.lower() in body:
                                    findings.append(self._make_finding(
                                        title=f"Sensitive File Exposed: {path}",
                                        severity=Severity.CRITICAL if "env" in path else Severity.HIGH,
                                        cvss_score=9.1 if "env" in path else 7.5,
                                        cwe_id="CWE-538", cwe_name="Sensitive Information in Externally-Accessible File",
                                        description=f"File at {path} is publicly accessible with sensitive data (matched: '{sig}').",
                                        evidence=f"URL: {url}\nHTTP {resp.status_code}\nPreview: {resp.text[:200]}",
                                        poc_steps=[f"Navigate to: {url}", f"Contains: {sig}"],
                                        remediation=f"Block access to {path}. Add server rules to deny dot-files.",
                                    ))
                                    break
                            continue
                        if resp.status_code == 200 and any(k in path.lower() for k in ["admin","manager","dashboard","panel","console","phpmyadmin","actuator","cpanel"]):
                            body_lower = resp.text.lower()
                            admin_kws = ["dashboard","admin panel","control panel","sign in","log in","username","password"]
                            if any(kw in body_lower for kw in admin_kws) or len(resp.text) > 500:
                                findings.append(self._make_finding(
                                    title=f"Admin Endpoint Accessible: {path}",
                                    severity=Severity.HIGH, cvss_score=7.5,
                                    cwe_id="CWE-284", cwe_name="Improper Access Control",
                                    description=f"Endpoint at {path} accessible without auth (HTTP {resp.status_code}).",
                                    evidence=f"URL: {url}\nStatus: {resp.status_code}\nLength: {len(resp.text)}",
                                    poc_steps=[f"Navigate to: {url}", "Admin content accessible without login"],
                                    remediation="Restrict admin endpoints via IP allowlist, VPN, or auth.",
                                ))
                        if path == "/.git/HEAD" and resp.status_code == 200 and "ref:" in resp.text:
                            findings.append(self._make_finding(
                                title="Git Repository Exposed", severity=Severity.HIGH, cvss_score=7.5,
                                cwe_id="CWE-538", cwe_name="Sensitive Info Exposed",
                                description=".git directory is public. Source code can be reconstructed.",
                                evidence=f"URL: {url}\nContent: {resp.text.strip()}",
                                remediation="Block .git/ in web server config.",
                            ))
                    except Exception:
                        continue
                for path in USER_DATA_PATHS:
                    url = base + path
                    try:
                        resp = await client.get(url, timeout=5.0)
                        if resp.status_code == 200:
                            body = resp.text.lower()
                            indicators = ["email","username","name","phone","address"]
                            if any(i in body for i in indicators) and len(resp.text) > 50:
                                findings.append(self._make_finding(
                                    title=f"Potential IDOR — User Data at {path}",
                                    severity=Severity.HIGH, cvss_score=7.5,
                                    cwe_id="CWE-639", cwe_name="Authorization Bypass via User-Controlled Key",
                                    description=f"Endpoint {path} returns user data without auth.",
                                    evidence=f"URL: {url}\nStatus: {resp.status_code}",
                                    poc_steps=["Change user ID (1→2) to access other users' data"],
                                    remediation="Implement authorization checks. Use UUIDs instead of sequential IDs.",
                                ))
                    except Exception:
                        continue
        except Exception as e:
            findings.append(self._make_finding(
                title="Access Control Scan Error", severity=Severity.INFO,
                description=str(e), evidence=str(e),
            ))
        if not findings:
            findings.append(self._make_finding(
                title="No Access Control Issues Detected", severity=Severity.INFO,
                description="No exposed admin panels, sensitive files, or IDOR found.",
            ))
        return findings
