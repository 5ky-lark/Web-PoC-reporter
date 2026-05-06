"""XSS Scanner — reflected XSS detection with raw HTTP capture."""

import httpx
import cvss
from scanners.base import BaseScanner, Finding, Confidence


XSS_PROBES = [
    {"payload": "<script>alert('XSS')</script>", "context": "html"},
    {"payload": '"><img src=x onerror=alert(1)>', "context": "attribute"},
    {"payload": "'-alert(1)-'", "context": "javascript"},
    {"payload": "<svg/onload=alert(1)>", "context": "html"},
    {"payload": "javascript:alert(1)", "context": "href"},
]

REFLECTION_CANARY = "cybersyc7x7test"


class XSSScanner(BaseScanner):
    name = "xss"
    description = "Cross-Site Scripting (XSS) Detection"

    async def scan(self, target_url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(
                timeout=15.0, follow_redirects=True, verify=False
            ) as client:
                resp, _ = await self.request(client, "GET", target_url)
                if resp is None:
                    return findings
                body = resp.text

                params = self._get_injectable_params(target_url, body)
                if not params:
                    return findings

                tested: set[str] = set()
                for param_info in params:
                    self.cancel_token.raise_if_cancelled()
                    name = param_info["name"]
                    test_url = param_info["url"]
                    if name in tested:
                        continue

                    canary_url = self._inject_param(test_url, name, REFLECTION_CANARY)
                    canary_resp, _ = await self.request(client, "GET", canary_url)
                    if canary_resp is None or REFLECTION_CANARY not in canary_resp.text:
                        continue
                    tested.add(name)

                    for probe in XSS_PROBES:
                        inject_url = self._inject_param(test_url, name, probe["payload"])
                        probe_resp, capture = await self.request(client, "GET", inject_url)
                        if probe_resp is None:
                            continue
                        if probe["payload"] in probe_resp.text:
                            findings.append(self._make_finding(
                                title=f"Reflected XSS in '{name}' parameter",
                                cvss_vector=cvss.vector("xss_reflected"),
                                cwe_id="CWE-79",
                                cwe_name="Improper Neutralization of Input During Web Page Generation",
                                description=(
                                    f"The '{name}' parameter reflects user input without "
                                    f"sanitization, allowing XSS in {probe['context']} context."
                                ),
                                evidence=f"Payload reflected: {probe['payload']}",
                                capture=capture,
                                poc_steps=[
                                    f"Open {inject_url} in a browser",
                                    f"The payload {probe['payload']} renders unencoded",
                                    "JavaScript would execute in any victim's browser",
                                ],
                                remediation=(
                                    "Sanitize and context-encode all user input before "
                                    "rendering. Apply a strict Content-Security-Policy."
                                ),
                                references=["https://owasp.org/www-community/attacks/xss/"],
                                target_url=inject_url,
                                parameter=name,
                                confidence=Confidence.REFLECTED,
                            ))
                            break

        except Exception as e:
            findings.append(self._make_finding(
                title="XSS scan error",
                cvss_score=0.0,
                description=str(e),
            ))
        return findings
