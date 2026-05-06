"""
Rate Limiting Scanner — Detects missing rate limiting on login/sensitive endpoints.
Sends rapid requests and checks if the server throttles or blocks.
"""

import asyncio
import time
import httpx
import re

from scanners.base import BaseScanner, Finding, Severity

# Common login/auth/sensitive endpoints to test
RATE_LIMIT_TARGETS = [
    {"path": "/login", "method": "POST", "type": "Login"},
    {"path": "/signin", "method": "POST", "type": "Login"},
    {"path": "/auth/login", "method": "POST", "type": "Login"},
    {"path": "/api/login", "method": "POST", "type": "API Login"},
    {"path": "/api/auth/login", "method": "POST", "type": "API Login"},
    {"path": "/api/auth/signin", "method": "POST", "type": "API Login"},
    {"path": "/register", "method": "POST", "type": "Registration"},
    {"path": "/signup", "method": "POST", "type": "Registration"},
    {"path": "/api/register", "method": "POST", "type": "API Registration"},
    {"path": "/forgot-password", "method": "POST", "type": "Password Reset"},
    {"path": "/api/forgot-password", "method": "POST", "type": "Password Reset"},
    {"path": "/api/otp/verify", "method": "POST", "type": "OTP Verification"},
    {"path": "/api/otp/send", "method": "POST", "type": "OTP Send"},
    {"path": "/contact", "method": "POST", "type": "Contact Form"},
    {"path": "/api/contact", "method": "POST", "type": "Contact Form"},
    {"path": "/search", "method": "GET", "type": "Search"},
    {"path": "/api/search", "method": "GET", "type": "API Search"},
]

# Number of rapid requests to test
BURST_COUNT = 15
# If all N requests succeed with same status, rate limiting is likely absent
RATE_LIMIT_INDICATORS = [429, 503]
RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "retry-after", "ratelimit-limit", "ratelimit-remaining",
]


class RateLimitScanner(BaseScanner):
    name = "ratelimit"
    description = "Rate Limiting & Abuse Testing"

    async def scan(self, target_url: str) -> list[Finding]:
        findings = []
        tested = 0
        missing_ratelimit = []

        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=False
            ) as client:
                # First, discover which endpoints actually exist
                existing_endpoints = []
                for target in RATE_LIMIT_TARGETS:
                    url = target_url.rstrip("/") + target["path"]
                    try:
                        if target["method"] == "POST":
                            resp = await client.post(
                                url,
                                data={"username": "test", "password": "test", "email": "test@test.com"},
                                timeout=5.0,
                            )
                        else:
                            resp = await client.get(url, timeout=5.0)

                        # Endpoint exists if not 404/405
                        if resp.status_code not in (404, 405, 501):
                            existing_endpoints.append({**target, "url": url, "status": resp.status_code})
                    except Exception:
                        continue

                if not existing_endpoints:
                    findings.append(self._make_finding(
                        title="No Login/Auth Endpoints Found for Rate Limit Testing",
                        severity=Severity.INFO,
                        description="No common authentication or sensitive endpoints were found to test for rate limiting.",
                    ))
                    return findings

                # Test rate limiting on each discovered endpoint
                for endpoint in existing_endpoints:
                    tested += 1
                    url = endpoint["url"]
                    endpoint_type = endpoint["type"]

                    statuses = []
                    has_ratelimit_headers = False

                    # Rapid-fire requests
                    for i in range(BURST_COUNT):
                        try:
                            if endpoint["method"] == "POST":
                                resp = await client.post(
                                    url,
                                    data={"username": f"bruteforce{i}", "password": f"wrong{i}"},
                                    timeout=5.0,
                                )
                            else:
                                resp = await client.get(url, timeout=5.0)

                            statuses.append(resp.status_code)

                            # Check for rate limit headers
                            for header in RATE_LIMIT_HEADERS:
                                if header in [h.lower() for h in resp.headers.keys()]:
                                    has_ratelimit_headers = True
                                    break

                            # If we get rate-limited, stop
                            if resp.status_code in RATE_LIMIT_INDICATORS:
                                break

                        except Exception:
                            break

                    # Analyze results
                    got_blocked = any(s in RATE_LIMIT_INDICATORS for s in statuses)

                    if not got_blocked and not has_ratelimit_headers and len(statuses) >= BURST_COUNT:
                        severity = Severity.HIGH if endpoint_type in ("Login", "API Login", "OTP Verification") else Severity.MEDIUM
                        cvss = 7.5 if severity == Severity.HIGH else 5.3

                        missing_ratelimit.append(endpoint_type)
                        findings.append(self._make_finding(
                            title=f"No Rate Limiting on {endpoint_type} ({endpoint['path']})",
                            severity=severity, cvss_score=cvss,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if severity == Severity.HIGH else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                            cwe_id="CWE-307",
                            cwe_name="Improper Restriction of Excessive Authentication Attempts",
                            description=f"The {endpoint_type.lower()} endpoint at {endpoint['path']} accepted {BURST_COUNT} rapid requests without any throttling or blocking. This allows brute force attacks.",
                            evidence=f"Endpoint: {url}\nMethod: {endpoint['method']}\nRequests sent: {BURST_COUNT}\nStatus codes: {statuses}\nRate limit headers: None detected\nBlocked: No",
                            poc_steps=[
                                f"Send {BURST_COUNT} rapid {endpoint['method']} requests to {endpoint['path']}",
                                f"All requests returned successfully (status codes: {set(statuses)})",
                                "No rate-limit headers (X-RateLimit-*, Retry-After) detected",
                                "An attacker can brute-force credentials without restriction",
                            ],
                            remediation="Implement rate limiting (e.g., 5 attempts per minute for login). Use progressive delays, CAPTCHA after failures, and account lockout policies. Return 429 status code when limits are exceeded.",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                                "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                            ],
                        ))
                    elif has_ratelimit_headers or got_blocked:
                        findings.append(self._make_finding(
                            title=f"Rate Limiting Detected on {endpoint_type} ({endpoint['path']})",
                            severity=Severity.INFO,
                            description=f"Rate limiting appears to be configured on {endpoint['path']}. {'Received 429 response.' if got_blocked else 'Rate limit headers detected.'}",
                        ))

        except Exception as e:
            findings.append(self._make_finding(
                title="Rate Limit Scan Error", severity=Severity.INFO,
                description=f"Error during rate limit testing: {str(e)}", evidence=str(e),
            ))

        if not findings:
            findings.append(self._make_finding(
                title="Rate Limit Test Complete",
                severity=Severity.INFO,
                description=f"Tested {tested} endpoints. No definitive rate limiting issues found.",
            ))

        return findings
