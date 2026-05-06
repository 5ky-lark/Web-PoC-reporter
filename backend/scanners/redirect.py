"""Open Redirect Scanner — URL redirection with raw HTTP capture."""

from urllib.parse import urlparse, parse_qs

import httpx

import cvss
from scanners.base import BaseScanner, Finding, Confidence


REDIRECT_PAYLOADS = [
    "https://evil.example",
    "//evil.example",
    "https://evil.example/%2f..",
    "/\\evil.example",
    "////evil.example",
]

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "next", "return", "returnTo", "return_url",
    "goto", "redir", "destination", "forward", "continue", "target", "link",
    "callback", "out",
]


class OpenRedirectScanner(BaseScanner):
    name = "redirect"
    description = "Open redirect detection"

    async def scan(self, target_url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(
                timeout=15.0, follow_redirects=False, verify=False
            ) as client:
                resp, _ = await self.request(client, "GET", target_url)
                if resp is None:
                    return findings
                params = self._get_injectable_params(target_url, resp.text)

                parsed = urlparse(target_url)
                query_params = parse_qs(parsed.query)
                for n in REDIRECT_PARAMS:
                    if n not in query_params and not any(p["name"] == n for p in params):
                        sep = "&" if parsed.query else "?"
                        params.append({"name": n, "url": f"{target_url}{sep}{n}=/"})

                for param_info in params:
                    self.cancel_token.raise_if_cancelled()
                    name = param_info["name"]
                    test_url = param_info["url"]
                    found = False
                    for payload in REDIRECT_PAYLOADS:
                        if found:
                            break
                        inject_url = self._inject_param(test_url, name, payload)
                        r, cap = await self.request(client, "GET", inject_url, timeout=10)
                        if r is None:
                            continue
                        location = r.headers.get("location", "")
                        if location and "evil.example" in location.lower():
                            findings.append(self._make_finding(
                                title=f"Open redirect via '{name}' parameter",
                                cvss_vector=cvss.vector("open_redirect"),
                                cwe_id="CWE-601",
                                cwe_name="URL Redirection to Untrusted Site",
                                description=(
                                    f"'{name}' redirects to attacker-controlled URLs. Common "
                                    f"vector for phishing — victims see the trusted hostname "
                                    f"in the link before being bounced off."
                                ),
                                evidence=f"Location header: {location}",
                                capture=cap,
                                poc_steps=[
                                    f"Send victim {inject_url}",
                                    f"Server replies {r.status_code} with Location: {location}",
                                    "Browser follows the redirect to attacker domain",
                                ],
                                remediation=(
                                    "Validate redirects against an allowlist of internal "
                                    "paths. Refuse off-host or scheme-changing redirects."
                                ),
                                references=[
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                                ],
                                target_url=inject_url,
                                parameter=name,
                                confidence=Confidence.EXECUTED,
                            ))
                            found = True

        except Exception as e:
            findings.append(self._make_finding(
                title="Open-redirect scan error",
                description=str(e),
            ))
        return findings
