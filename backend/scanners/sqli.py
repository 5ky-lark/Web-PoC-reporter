"""SQL Injection Scanner — error-based + time-based with raw HTTP capture."""

import re
import time

import httpx

import cvss
from scanners.base import BaseScanner, Finding, Confidence


SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for (sql server|odbc drivers)",
    r"pg_(query|exec)\(\):",
    r"postgresql.*error",
    r"ora-\d{5}",
    r"oracle.*error",
    r"sqlite3?\.OperationalError",
    r"sql syntax.*mysql",
    r"valid mysql result",
    r"mssql_query\(\)",
    r"syntax error.*sql",
    r"SQLSTATE\[",
    r"mysql_(fetch|num_rows)",
]

ERROR_PAYLOADS = [
    "'", '"', "' OR '1'='1", '" OR "1"="1', "1' ORDER BY 1--", "1 UNION SELECT NULL--",
]
TIME_PAYLOADS = [
    ("' OR SLEEP(5)-- ", 5),
    ("'; WAITFOR DELAY '0:0:5'-- ", 5),
    ("' OR pg_sleep(5)-- ", 5),
]


class SQLiScanner(BaseScanner):
    name = "sqli"
    description = "SQL Injection Detection"

    async def scan(self, target_url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(
                timeout=20.0, follow_redirects=True, verify=False
            ) as client:
                resp, _ = await self.request(client, "GET", target_url)
                if resp is None:
                    return findings
                body = resp.text

                params = self._get_injectable_params(target_url, body)
                if not params:
                    return findings

                for param_info in params:
                    self.cancel_token.raise_if_cancelled()
                    name = param_info["name"]
                    test_url = param_info["url"]
                    found = False

                    # Error-based
                    for payload in ERROR_PAYLOADS:
                        if found:
                            break
                        inject_url = self._inject_param(test_url, name, payload)
                        r, cap = await self.request(client, "GET", inject_url)
                        if r is None:
                            continue
                        text = r.text.lower()
                        for pattern in SQL_ERROR_PATTERNS:
                            if re.search(pattern, text, re.IGNORECASE):
                                findings.append(self._make_finding(
                                    title=f"SQL injection in '{name}' (error-based)",
                                    cvss_vector=cvss.vector("sqli_error"),
                                    cwe_id="CWE-89",
                                    cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
                                    description=(
                                        f"SQL error revealed when injecting {payload!r} into "
                                        f"'{name}'. A database-error is leaking, indicating "
                                        f"unsanitized SQL string concatenation."
                                    ),
                                    evidence=f"Payload {payload!r} matched DB error pattern: {pattern}",
                                    capture=cap,
                                    poc_steps=[
                                        f"Open {inject_url}",
                                        "Database error leaks in the response body",
                                        "Confirms unparameterized SQL — extract data with UNION or boolean payloads",
                                    ],
                                    remediation=(
                                        "Use parameterized queries / prepared statements. Never "
                                        "concatenate user input into SQL. Suppress detailed DB "
                                        "errors in production responses."
                                    ),
                                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                                    target_url=inject_url,
                                    parameter=name,
                                    confidence=Confidence.EXECUTED,
                                ))
                                found = True
                                break

                    # Time-based blind
                    if found:
                        continue
                    for payload, delay in TIME_PAYLOADS:
                        inject_url = self._inject_param(test_url, name, payload)
                        start = time.time()
                        r, cap = await self.request(
                            client, "GET", inject_url, timeout=delay + 5
                        )
                        elapsed = time.time() - start
                        if r is not None and elapsed >= delay - 1:
                            findings.append(self._make_finding(
                                title=f"Blind SQL injection in '{name}' (time-based)",
                                cvss_vector=cvss.vector("sqli_blind"),
                                cwe_id="CWE-89",
                                cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
                                description=(
                                    f"Response delayed ~{elapsed:.1f}s when sending a "
                                    f"time-delay payload, vs. expected sub-second normally."
                                ),
                                evidence=f"Expected ≥{delay}s, observed {elapsed:.1f}s",
                                capture=cap,
                                poc_steps=[
                                    f"Send {inject_url}",
                                    f"Server response is delayed by ~{delay}s",
                                    "Boolean blind SQLi can extract row data character-by-character",
                                ],
                                remediation="Use parameterized queries. Apply input validation.",
                                references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                                target_url=inject_url,
                                parameter=name,
                                confidence=Confidence.EXECUTED,
                            ))
                            break

        except Exception as e:
            findings.append(self._make_finding(
                title="SQLi scan error",
                description=str(e),
            ))
        return findings
