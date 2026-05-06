"""
Scan Orchestrator — DB-backed, cancel-aware, throttled.

Stages:
  Stage 0  Crawler                            (sequential)
  Stage 1  Recon (headers/ssl/ports/tech/...) (parallel)
  Stage 2  Injection (xss/sqli/cmdi/...)      (parallel, uses crawl data)
  Stage 3  CVE lookup                         (depends on tech fingerprint)

Every scan persists to SQLite. Every HTTP-issuing module respects a
per-host throttle. Operators can cancel mid-flight via cancel().
"""

from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import WebSocket

import db
import cvss as cvss_mod
from throttle import CancelToken, CancelledScan
from scanners.base import (
    BaseScanner,
    Finding,
    ScanProgress,
    ScanResult,
    Severity,
    fingerprint_for,
)
from scanners.headers import HeaderScanner
from scanners.ssl_scanner import SSLScanner
from scanners.ports import PortScanner
from scanners.tech import TechFingerprinter
from scanners.xss import XSSScanner
from scanners.sqli import SQLiScanner
from scanners.cors import CORSScanner
from scanners.clickjack import ClickjackScanner
from scanners.cve import CVELookup
from scanners.cmdi import CommandInjectionScanner
from scanners.pathtraversal import PathTraversalScanner
from scanners.session import SessionScanner
from scanners.redirect import OpenRedirectScanner
from scanners.ratelimit import RateLimitScanner
from scanners.accesscontrol import AccessControlScanner
from scanners.apisecurity import APISecurityScanner
from scanners.crawler import CrawlerScanner


AVAILABLE_MODULES: dict[str, type[BaseScanner]] = {
    "crawler": CrawlerScanner,
    "headers": HeaderScanner,
    "ssl": SSLScanner,
    "ports": PortScanner,
    "tech": TechFingerprinter,
    "xss": XSSScanner,
    "sqli": SQLiScanner,
    "cmdi": CommandInjectionScanner,
    "pathtraversal": PathTraversalScanner,
    "cors": CORSScanner,
    "clickjack": ClickjackScanner,
    "session": SessionScanner,
    "redirect": OpenRedirectScanner,
    "ratelimit": RateLimitScanner,
    "accesscontrol": AccessControlScanner,
    "apisecurity": APISecurityScanner,
    "cve": CVELookup,
}

PRE_MODULES = {"crawler"}
RECON_MODULES = {"headers", "ssl", "ports", "tech", "session", "cors", "clickjack"}
INJECTION_MODULES = {
    "xss", "sqli", "cmdi", "pathtraversal", "redirect",
    "ratelimit", "accesscontrol", "apisecurity",
}
POST_MODULES = {"cve"}


PROFILES: dict[str, list[str]] = {
    "recon": [
        "crawler", "headers", "ssl", "ports", "tech", "session",
        "cors", "clickjack", "cve",
    ],
    "standard": [
        "crawler", "headers", "ssl", "tech", "session", "cors", "clickjack",
        "xss", "sqli", "cmdi", "pathtraversal", "redirect", "cve",
    ],
    "deep": list(AVAILABLE_MODULES.keys()),
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanOrchestrator:
    """Persists every scan and finding. Cancellable. Throttled."""

    def __init__(self) -> None:
        # cancel tokens for currently-running scans, keyed by scan_id
        self._cancel_tokens: dict[str, CancelToken] = {}
        # in-memory tracking-id counters, keyed by (engagement_id, module)
        self._tracking_counters: dict[tuple[str, str], int] = defaultdict(int)

    # ---- public API ----

    def create_scan(
        self,
        target_url: str,
        modules: Optional[list[str]] = None,
        *,
        engagement_id: Optional[str] = None,
        profile: str = "standard",
    ) -> str:
        scan_id = str(uuid.uuid4())
        chosen = modules or PROFILES.get(profile, PROFILES["standard"])
        chosen = [m for m in chosen if m in AVAILABLE_MODULES]

        db.insert_scan({
            "id": scan_id,
            "engagement_id": engagement_id,
            "target_url": target_url,
            "profile": profile,
            "modules_run": chosen,
            "status": "pending",
            "started_at": now_iso(),
        })
        db.log_event(
            "scan_created",
            scan_id=scan_id, engagement_id=engagement_id,
            details={"target_url": target_url, "profile": profile, "modules": chosen},
        )
        return scan_id

    def cancel(self, scan_id: str) -> bool:
        """Operator kill-switch. Returns True if a token existed to cancel."""
        token = self._cancel_tokens.get(scan_id)
        if not token:
            return False
        token.cancel()
        return True

    async def run_scan(
        self,
        scan_id: str,
        websocket: Optional[WebSocket] = None,
    ) -> Optional[ScanResult]:
        scan = db.get_scan(scan_id)
        if not scan:
            return None

        cancel = CancelToken()
        self._cancel_tokens[scan_id] = cancel

        modules: list[str] = scan["modules_run"] or []
        total = max(len(modules), 1)
        completed = 0
        all_findings: list[Finding] = []
        crawl_data = None
        tech_data: dict = {}
        errors: list[str] = []

        db.update_scan(scan_id, status="running")
        db.log_event("scan_started", scan_id=scan_id)

        async def emit(progress: ScanProgress) -> None:
            if websocket:
                try:
                    await websocket.send_json(progress.model_dump())
                except Exception:
                    pass

        async def run_module(name: str) -> list[Finding]:
            nonlocal completed, tech_data
            cls = AVAILABLE_MODULES.get(name)
            if not cls:
                completed += 1
                errors.append(f"unknown module: {name}")
                return []
            scanner = cls()
            scanner.cancel_token = cancel
            if crawl_data:
                scanner.crawl_data = crawl_data

            await emit(ScanProgress(
                module=name, status="running",
                progress=round((completed / total) * 100, 1),
                message=f"{scanner.description}",
            ))

            try:
                if name == "cve" and tech_data:
                    scanner.detected_technologies = tech_data
                results = await scanner.scan(scan["target_url"])
                if name == "tech" and hasattr(scanner, "detected_tech"):
                    tech_data = scanner.detected_tech
                completed += 1
                await emit(ScanProgress(
                    module=name, status="complete",
                    progress=round((completed / total) * 100, 1),
                    message=f"{scanner.description} — {len(results)} finding(s)",
                    findings=results,
                ))
                return results
            except CancelledScan:
                completed += 1
                await emit(ScanProgress(
                    module=name, status="cancelled",
                    progress=round((completed / total) * 100, 1),
                    message=f"{name} cancelled by operator",
                ))
                return []
            except Exception as e:
                completed += 1
                errors.append(f"{name}: {e}")
                await emit(ScanProgress(
                    module=name, status="error",
                    progress=round((completed / total) * 100, 1),
                    message=f"{name} error: {e}",
                ))
                return []

        try:
            pre = [m for m in modules if m in PRE_MODULES]
            recon = [m for m in modules if m in RECON_MODULES]
            injection = [m for m in modules if m in INJECTION_MODULES]
            post = [m for m in modules if m in POST_MODULES]

            # Stage 0: crawler (sequential, populates crawl_data)
            for name in pre:
                if cancel.is_cancelled:
                    break
                cls = AVAILABLE_MODULES.get(name)
                if not cls:
                    continue
                scanner = cls()
                scanner.cancel_token = cancel
                await emit(ScanProgress(
                    module=name, status="running",
                    progress=0, message="Discovering attack surface",
                ))
                try:
                    findings = await scanner.scan(scan["target_url"])
                    all_findings.extend(findings)
                    if hasattr(scanner, "crawl_result"):
                        crawl_data = scanner.crawl_result
                    completed += 1
                    msg = (
                        f"Found {len(crawl_data.urls)} pages, {len(crawl_data.params)} params"
                        if crawl_data else "Complete"
                    )
                    await emit(ScanProgress(
                        module=name, status="complete",
                        progress=round((completed / total) * 100, 1),
                        message=msg, findings=findings,
                    ))
                except CancelledScan:
                    completed += 1
                except Exception as e:
                    completed += 1
                    errors.append(f"{name}: {e}")

            if not cancel.is_cancelled and recon:
                for fs in await asyncio.gather(*[run_module(m) for m in recon]):
                    all_findings.extend(fs)

            if not cancel.is_cancelled and injection:
                for fs in await asyncio.gather(*[run_module(m) for m in injection]):
                    all_findings.extend(fs)

            if not cancel.is_cancelled and post:
                for fs in await asyncio.gather(*[run_module(m) for m in post]):
                    all_findings.extend(fs)

        except Exception as e:
            errors.append(f"orchestrator: {e}")

        # Reconcile severity through vector once more for safety, then persist
        for f in all_findings:
            if f.cvss_vector:
                score, sev = cvss_mod.derive(f.cvss_vector, f.cvss_score)
                f.cvss_score = score
                f.severity = Severity(sev)

        # Assign stable, human-readable tracking IDs.
        # Reuse fingerprints across scans on the same engagement.
        self._assign_tracking_ids(all_findings, scan.get("engagement_id"))

        # Persist findings
        if all_findings:
            db.insert_findings([
                {**f.model_dump(), "scan_id": scan_id} for f in all_findings
            ])

        cancelled = cancel.is_cancelled
        summary = self._summarize(all_findings)

        db.update_scan(
            scan_id,
            status="cancelled" if cancelled else "completed",
            completed_at=now_iso() if not cancelled else None,
            cancelled_at=now_iso() if cancelled else None,
            errors=errors,
            summary=summary,
        )
        db.log_event(
            "scan_cancelled" if cancelled else "scan_completed",
            scan_id=scan_id,
            details={"total": len(all_findings), "summary": summary},
        )

        # Final WS message
        if websocket:
            try:
                await websocket.send_json({
                    "type": "scan_cancelled" if cancelled else "scan_complete",
                    "scan_id": scan_id,
                    "summary": summary,
                    "total_findings": len(all_findings),
                })
            except Exception:
                pass

        # Cleanup
        self._cancel_tokens.pop(scan_id, None)

        result = ScanResult(
            scan_id=scan_id,
            target_url=scan["target_url"],
            status="cancelled" if cancelled else "completed",
            started_at=scan["started_at"],
            completed_at=now_iso() if not cancelled else "",
            cancelled_at=now_iso() if cancelled else "",
            findings=all_findings,
            summary=summary,
            modules_run=modules,
            errors=errors,
            profile=scan.get("profile") or "standard",
            engagement_id=scan.get("engagement_id"),
        )
        return result

    # ---- helpers ----

    def get_scan(self, scan_id: str) -> Optional[dict]:
        scan = db.get_scan(scan_id)
        if not scan:
            return None
        scan["findings"] = db.list_findings_for_scan(scan_id)
        return scan

    def _summarize(self, findings: list[Finding]) -> dict:
        s = {"total": len(findings), "critical": 0, "high": 0,
             "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else f.severity
            if sev in s:
                s[sev] += 1
        return s

    def _assign_tracking_ids(
        self, findings: list[Finding], engagement_id: Optional[str]
    ) -> None:
        """Stable, human-readable IDs (CYS-XSS-0007) per fingerprint within an engagement."""
        eid = engagement_id or "_global"
        seen: dict[str, str] = {}  # fingerprint -> tracking_id
        for f in findings:
            if not f.fingerprint:
                continue
            if f.fingerprint in seen:
                f.tracking_id = seen[f.fingerprint]
                continue
            mod_token = f.module.upper()[:3]
            key = (eid, mod_token)
            self._tracking_counters[key] += 1
            tid = f"CYS-{mod_token}-{self._tracking_counters[key]:04d}"
            f.tracking_id = tid
            seen[f.fingerprint] = tid
