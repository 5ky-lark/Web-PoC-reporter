"""CORS Scanner — origin reflection / wildcard / null with raw HTTP capture."""

import httpx

import cvss
from scanners.base import BaseScanner, Finding, Confidence


class CORSScanner(BaseScanner):
    name = "cors"
    description = "CORS misconfiguration detection"

    async def scan(self, target_url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(
                timeout=15.0, follow_redirects=True, verify=False
            ) as client:
                evil_origin = "https://evil-attacker.example"
                hdrs = {"Origin": evil_origin}
                resp, cap = await self.request(client, "GET", target_url, headers=hdrs)
                if resp is None:
                    return findings
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "").lower()

                if acao == evil_origin:
                    with_creds = (acac == "true")
                    findings.append(self._make_finding(
                        title=("CORS origin reflection with credentials"
                               if with_creds else "CORS origin reflection"),
                        cvss_vector=cvss.vector(
                            "cors_reflect_creds" if with_creds else "cors_reflect"
                        ),
                        cwe_id="CWE-942",
                        cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
                        description=(
                            "The server reflects arbitrary Origin headers in "
                            "Access-Control-Allow-Origin. " +
                            ("Credentials are also allowed, enabling full cross-origin "
                             "data theft from authenticated victims."
                             if with_creds else
                             "Attacker JavaScript can read responses cross-origin.")
                        ),
                        evidence=(
                            f"Sent Origin: {evil_origin}\n"
                            f"Got Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac or '(absent)'}"
                        ),
                        capture=cap,
                        poc_steps=[
                            f"Send GET {target_url} with header Origin: {evil_origin}",
                            f"Response includes Access-Control-Allow-Origin: {evil_origin}",
                            "Attacker page on evil-attacker.example can fetch and exfiltrate the response",
                        ],
                        remediation=(
                            "Whitelist specific trusted origins instead of reflecting "
                            "the Origin header. Never combine credential support with "
                            "permissive origins."
                        ),
                        references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                        target_url=target_url,
                        confidence=Confidence.EXECUTED,
                    ))

                if acao == "*" and acac == "true":
                    findings.append(self._make_finding(
                        title="CORS wildcard with credentials",
                        cvss_vector=cvss.vector("cors_wildcard_creds"),
                        cwe_id="CWE-942",
                        cwe_name="Permissive Cross-domain Policy",
                        description=(
                            "Access-Control-Allow-Origin: * combined with "
                            "Access-Control-Allow-Credentials: true. Browsers refuse "
                            "this combination, but the server is misconfigured."
                        ),
                        evidence=f"ACAO: {acao}\nACAC: {acac}",
                        capture=cap,
                        remediation="Never use wildcard with credentials. Use a strict allowlist.",
                        target_url=target_url,
                        confidence=Confidence.EXECUTED,
                    ))

                # Null origin
                resp_null, cap_null = await self.request(
                    client, "GET", target_url, headers={"Origin": "null"}
                )
                if resp_null is not None and resp_null.headers.get(
                    "access-control-allow-origin", ""
                ) == "null":
                    findings.append(self._make_finding(
                        title="CORS accepts null origin",
                        cvss_vector=cvss.vector("cors_null"),
                        cwe_id="CWE-942",
                        cwe_name="Permissive Cross-domain Policy",
                        description=(
                            "The server accepts 'null' as a valid origin. Sandboxed iframes "
                            "and data: URIs send Origin: null — this bypasses CORS for them."
                        ),
                        evidence="Origin: null → ACAO: null",
                        capture=cap_null,
                        poc_steps=[
                            "Host attacker page in a sandboxed iframe (Origin becomes null)",
                            f"Issue cross-origin fetch to {target_url}",
                            "Server responds with Access-Control-Allow-Origin: null and the response is readable",
                        ],
                        remediation="Do not include 'null' in your CORS allowlist.",
                        target_url=target_url,
                        confidence=Confidence.EXECUTED,
                    ))

        except Exception as e:
            findings.append(self._make_finding(
                title="CORS scan error",
                description=str(e),
            ))
        return findings
