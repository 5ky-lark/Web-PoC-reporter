"""Command Injection Scanner — OS command injection with raw HTTP capture."""

import re
import httpx

import cvss
from scanners.base import BaseScanner, Finding, Confidence


CMD_PAYLOADS = [
    {"payload": ";id", "pattern": r"uid=\d+", "os": "Linux"},
    {"payload": "|id", "pattern": r"uid=\d+", "os": "Linux"},
    {"payload": "`id`", "pattern": r"uid=\d+", "os": "Linux"},
    {"payload": "$(id)", "pattern": r"uid=\d+", "os": "Linux"},
    {"payload": ";whoami", "pattern": r"(root|www-data|apache|nginx|nobody)", "os": "Linux"},
    {"payload": "|dir", "pattern": r"<DIR>|Volume Serial Number", "os": "Windows"},
    {"payload": "&dir", "pattern": r"<DIR>|Volume Serial Number", "os": "Windows"},
]


class CommandInjectionScanner(BaseScanner):
    name = "cmdi"
    description = "OS command injection detection"

    async def scan(self, target_url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(
                timeout=15.0, follow_redirects=True, verify=False
            ) as client:
                resp, _ = await self.request(client, "GET", target_url)
                if resp is None:
                    return findings
                params = self._get_injectable_params(target_url, resp.text)
                if not params:
                    return findings

                for param_info in params:
                    self.cancel_token.raise_if_cancelled()
                    name = param_info["name"]
                    test_url = param_info["url"]
                    hit = False
                    for probe in CMD_PAYLOADS:
                        if hit:
                            break
                        inject_url = self._inject_param(test_url, name, probe["payload"])
                        r, cap = await self.request(client, "GET", inject_url, timeout=10)
                        if r is None:
                            continue
                        if re.search(probe["pattern"], r.text, re.IGNORECASE):
                            findings.append(self._make_finding(
                                title=f"OS command injection in '{name}' ({probe['os']})",
                                cvss_vector=cvss.vector("cmdi"),
                                cwe_id="CWE-78",
                                cwe_name="Improper Neutralization of Special Elements used in an OS Command",
                                description=(
                                    f"Payload {probe['payload']!r} returned OS command output "
                                    f"in the response, demonstrating shell execution."
                                ),
                                evidence=f"Pattern matched: {probe['pattern']}",
                                capture=cap,
                                poc_steps=[
                                    f"Send GET {inject_url}",
                                    f"Response body contains OS command output ({probe['pattern']})",
                                    "Pivot to remote-code-execution by chaining commands",
                                ],
                                remediation=(
                                    "Never pass user input to shell commands. Use parameterized "
                                    "subprocess APIs and strict allowlists. Drop privileges."
                                ),
                                references=["https://owasp.org/www-community/attacks/Command_Injection"],
                                target_url=inject_url,
                                parameter=name,
                                confidence=Confidence.EXECUTED,
                            ))
                            hit = True

        except Exception as e:
            findings.append(self._make_finding(
                title="Command-injection scan error",
                description=str(e),
            ))
        return findings
