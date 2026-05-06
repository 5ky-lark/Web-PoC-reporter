"""
Base scanner module — Finding data model + abstract BaseScanner class.

Key changes from v1:
  - Severity is *derived* from the CVSS vector, never asserted alongside an
    inconsistent score. Fixes the cvss=6.1 + severity=HIGH bug.
  - Finding carries raw HTTP request, raw response, and a curl reproducer —
    that's the whole point of a "PoC reporter".
  - Stable fingerprint on every Finding for cross-scan diff.
  - Tracking ID is human-readable (CYS-XSS-0007) and stable per fingerprint.
  - Confidence levels: heuristic | reflected | executed | operator_confirmed.
  - Cancel-token aware: raise_if_cancelled() between probes.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, model_validator

import cvss as cvss_mod
from throttle import (
    THROTTLE,
    CancelToken,
    CancelledScan,
    capture as capture_http,
    host_of,
)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HEURISTIC = "heuristic"            # pattern matched, not exploited
    REFLECTED = "reflected"            # canary reflected, no exec
    EXECUTED = "executed"              # payload demonstrably executed
    CONFIRMED = "operator_confirmed"   # set by an operator, not the scanner


def severity_from_cvss(score: float) -> Severity:
    """Single source: score -> severity."""
    return Severity(cvss_mod.severity_from_score(score))


class Finding(BaseModel):
    """Standardized vulnerability finding produced by all scan modules."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tracking_id: str = ""              # CYS-XSS-0007, set by orchestrator
    title: str
    module: str
    severity: Severity
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    description: str = ""

    # Evidence: prose + structured artifacts
    evidence: str = ""
    evidence_request: str = ""         # raw HTTP request
    evidence_response: str = ""        # raw HTTP response (truncated)
    evidence_curl: str = ""            # one-line curl reproducer

    poc_steps: list[str] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    # Cross-scan identity + operator workflow
    target_url: str = ""               # specific URL where the finding lives
    fingerprint: str = ""              # stable hash for diffing across scans
    confidence: Confidence = Confidence.HEURISTIC
    epss: Optional[float] = None       # exploit prediction percentile
    kev: bool = False                  # CISA Known Exploited Vulnerability
    status: str = "new"
    severity_override: Optional[Severity] = None
    severity_override_reason: str = ""
    discovered_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @model_validator(mode="after")
    def _derive_severity_from_vector(self) -> "Finding":
        """If a CVSS vector was given, the score and severity are *derived* from it.
        Inconsistent (vector, score, severity) triples are silently corrected."""
        if self.cvss_vector:
            score, sev = cvss_mod.derive(self.cvss_vector, self.cvss_score)
            self.cvss_score = score
            self.severity = Severity(sev)
        return self


class ScanProgress(BaseModel):
    """Progress update sent via WebSocket during scanning."""
    module: str
    status: str  # running | complete | error | cancelled
    progress: float
    message: str = ""
    findings: list[Finding] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Complete scan result with all findings and summary."""
    scan_id: str
    target_url: str
    status: str
    started_at: str = ""
    completed_at: str = ""
    cancelled_at: str = ""
    findings: list[Finding] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
    modules_run: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    profile: str = "standard"
    engagement_id: Optional[str] = None


# -------- Fingerprinting --------

def fingerprint_for(
    *,
    module: str,
    cwe_id: str,
    target_url: str,
    parameter: str = "",
    title: str = "",
) -> str:
    """Stable hash for cross-scan identity. Same fingerprint = same finding.

    Uses host + path (drops query) + module + cwe + parameter + title-canonical."""
    p = urlparse(target_url)
    host_path = f"{(p.hostname or '').lower()}{p.path or '/'}"
    title_canon = re.sub(r"['\"`]", "", title.lower())
    title_canon = re.sub(r"\s+", " ", title_canon).strip()
    raw = "|".join([module, cwe_id, host_path, parameter, title_canon])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# -------- Base scanner --------

class BaseScanner(ABC):
    """Abstract base class for all scan modules."""

    name: str = "base"
    description: str = "Base scanner"

    # Set by orchestrator before scan() is called
    crawl_data: Any = None
    cancel_token: CancelToken = CancelToken()

    # ---- API ----

    @abstractmethod
    async def scan(self, target_url: str) -> list[Finding]:
        """Execute the scan and return findings. Must respect cancel_token."""

    # ---- HTTP helpers ----

    async def request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        headers: Optional[dict] = None,
        body: Optional[str] = None,
        timeout: float = 12.0,
    ) -> tuple[Optional[httpx.Response], dict]:
        """Throttled HTTP request. Returns (response, capture_dict).

        capture_dict has evidence_request / evidence_response / evidence_curl
        ready to drop into a Finding. On error returns (None, {})."""
        self.cancel_token.raise_if_cancelled()
        host = host_of(url)
        try:
            async with THROTTLE.slot(host):
                if method.upper() == "GET":
                    resp = await client.get(url, headers=headers or {}, timeout=timeout)
                elif method.upper() == "POST":
                    resp = await client.post(
                        url, headers=headers or {}, content=body, timeout=timeout
                    )
                else:
                    resp = await client.request(
                        method, url, headers=headers or {}, content=body, timeout=timeout
                    )
        except Exception:
            return None, {}
        return resp, capture_http(method, url, resp, headers, body)

    # ---- Param helpers ----

    def _get_injectable_params(self, target_url: str, body: str = "") -> list[dict]:
        """Get all injectable parameters, combining page params with crawl data."""
        from scanners.params import extract_params
        params = extract_params(target_url, body)
        if self.crawl_data and hasattr(self.crawl_data, "params"):
            seen = {(p.get("url", "").split("?")[0], p["name"]) for p in params}
            for p in self.crawl_data.params:
                key = (p.get("url", "").split("?")[0], p["name"])
                if key not in seen:
                    seen.add(key)
                    params.append(p)
        return params

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from scanners.params import inject_param
        return inject_param(url, param, value)

    # ---- Finding factory ----

    def _make_finding(
        self,
        title: str,
        *,
        cvss_vector: str = "",
        cvss_score: float = 0.0,
        severity: Optional[Severity] = None,
        cwe_id: str = "",
        cwe_name: str = "",
        description: str = "",
        evidence: str = "",
        capture: Optional[dict] = None,
        poc_steps: Optional[list[str]] = None,
        remediation: str = "",
        references: Optional[list[str]] = None,
        target_url: str = "",
        parameter: str = "",
        confidence: Confidence = Confidence.HEURISTIC,
    ) -> Finding:
        """Build a Finding. Severity and cvss_score are derived from the vector
        when one is supplied — caller should pass `cvss_vector=cvss.vector('xss_reflected')`
        rather than hardcoding scores."""
        if cvss_vector:
            score, sev_str = cvss_mod.derive(cvss_vector, cvss_score)
            sev = Severity(sev_str)
        elif severity:
            score = cvss_score
            sev = severity
        else:
            score = cvss_score
            sev = severity_from_cvss(cvss_score)

        cap = capture or {}
        fp = fingerprint_for(
            module=self.name,
            cwe_id=cwe_id,
            target_url=target_url or "",
            parameter=parameter,
            title=title,
        )

        return Finding(
            title=title,
            module=self.name,
            severity=sev,
            cvss_score=score,
            cvss_vector=cvss_vector,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            description=description,
            evidence=evidence,
            evidence_request=cap.get("evidence_request", ""),
            evidence_response=cap.get("evidence_response", ""),
            evidence_curl=cap.get("evidence_curl", ""),
            poc_steps=poc_steps or [],
            remediation=remediation,
            references=references or [],
            target_url=target_url,
            fingerprint=fp,
            confidence=confidence,
        )
