"""
API Security Scanner — Discovers exposed API endpoints and checks for
missing auth, documentation exposure, and data overexposure.
"""
import httpx
import re
from scanners.base import BaseScanner, Finding, Severity

API_DOCS_PATHS = [
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api/docs", "/api/swagger", "/api/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api/openapi.json",
    "/docs", "/redoc", "/graphql", "/graphiql",
    "/api/v1/docs", "/api/v2/docs",
]

API_ENDPOINTS = [
    "/api", "/api/v1", "/api/v2", "/api/health", "/api/status",
    "/api/config", "/api/settings", "/api/info",
    "/api/users", "/api/products", "/api/orders", "/api/data",
    "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/graphql",
]

SENSITIVE_FIELDS = [
    "password", "secret", "token", "api_key", "apikey", "api-key",
    "private_key", "ssn", "credit_card", "creditcard", "card_number",
    "cvv", "bank_account", "access_token", "refresh_token",
]


class APISecurityScanner(BaseScanner):
    name = "apisecurity"
    description = "API Security & Exposure Testing"

    async def scan(self, target_url: str) -> list[Finding]:
        findings = []
        base = target_url.rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
                # 1. Check for exposed API documentation
                for path in API_DOCS_PATHS:
                    url = base + path
                    try:
                        resp = await client.get(url, timeout=5.0)
                        if resp.status_code == 200 and len(resp.text) > 100:
                            body_lower = resp.text.lower()
                            is_api_doc = any(kw in body_lower for kw in [
                                "swagger", "openapi", "api documentation",
                                "paths", "endpoints", "graphql", "schema",
                            ])
                            if is_api_doc:
                                findings.append(self._make_finding(
                                    title=f"API Documentation Exposed: {path}",
                                    severity=Severity.MEDIUM, cvss_score=5.3,
                                    cwe_id="CWE-200", cwe_name="Exposure of Sensitive Information",
                                    description=f"API documentation at {path} is publicly accessible. Attackers can enumerate all endpoints, parameters, and data models.",
                                    evidence=f"URL: {url}\nHTTP {resp.status_code}\nLength: {len(resp.text)}",
                                    poc_steps=[f"Navigate to: {url}", "Full API schema/docs are visible"],
                                    remediation="Restrict API documentation to authenticated users or internal networks only.",
                                ))
                    except Exception:
                        continue

                # 2. Check API endpoints for missing auth
                for path in API_ENDPOINTS:
                    url = base + path
                    try:
                        resp = await client.get(url, timeout=5.0)
                        if resp.status_code == 200:
                            content_type = resp.headers.get("content-type", "")
                            if "json" in content_type or resp.text.strip().startswith(("{", "[")):
                                body_lower = resp.text.lower()
                                exposed_sensitive = [f for f in SENSITIVE_FIELDS if f in body_lower]
                                if exposed_sensitive:
                                    findings.append(self._make_finding(
                                        title=f"Data Overexposure on API: {path}",
                                        severity=Severity.HIGH, cvss_score=7.5,
                                        cwe_id="CWE-213", cwe_name="Exposure of Sensitive Information Due to Incompatible Policies",
                                        description=f"API at {path} returns sensitive fields without auth: {', '.join(exposed_sensitive)}",
                                        evidence=f"URL: {url}\nSensitive fields: {exposed_sensitive}\nPreview: {resp.text[:300]}",
                                        poc_steps=[f"GET {url}", f"Response contains: {exposed_sensitive}"],
                                        remediation="Remove sensitive fields from API responses. Implement field-level access control.",
                                    ))
                                elif len(resp.text) > 50:
                                    findings.append(self._make_finding(
                                        title=f"API Endpoint Accessible Without Auth: {path}",
                                        severity=Severity.LOW, cvss_score=3.7,
                                        cwe_id="CWE-306", cwe_name="Missing Authentication for Critical Function",
                                        description=f"API at {path} returns data without authentication.",
                                        evidence=f"URL: {url}\nStatus: {resp.status_code}\nContent-Type: {content_type}",
                                        remediation="Require authentication (Bearer token, API key) for all API endpoints.",
                                    ))
                    except Exception:
                        continue

                # 3. Check for GraphQL introspection
                graphql_url = base + "/graphql"
                try:
                    resp = await client.post(
                        graphql_url,
                        json={"query": "{ __schema { types { name } } }"},
                        timeout=5.0,
                    )
                    if resp.status_code == 200 and "__schema" in resp.text:
                        findings.append(self._make_finding(
                            title="GraphQL Introspection Enabled",
                            severity=Severity.MEDIUM, cvss_score=5.3,
                            cwe_id="CWE-200", cwe_name="Information Exposure",
                            description="GraphQL introspection is enabled, exposing the full API schema including all types, queries, and mutations.",
                            evidence=f"URL: {graphql_url}\nIntrospection query returned __schema",
                            remediation="Disable GraphQL introspection in production.",
                        ))
                except Exception:
                    pass

        except Exception as e:
            findings.append(self._make_finding(
                title="API Security Scan Error", severity=Severity.INFO,
                description=str(e), evidence=str(e),
            ))
        if not findings:
            findings.append(self._make_finding(
                title="No API Security Issues Detected", severity=Severity.INFO,
                description="No exposed API docs, missing auth, or data overexposure found.",
            ))
        return findings
