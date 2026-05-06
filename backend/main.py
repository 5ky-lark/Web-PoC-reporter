"""
FastAPI entry point — engagements, scans, findings, exports, diff, audit.

Routes:
  /api/health
  /api/engagements                       (POST list / GET list)
  /api/engagements/{eid}                 (GET / PATCH)
  /api/scan                              (POST start)
  /api/scans                             (GET list)
  /api/scan/{sid}                        (GET / DELETE)
  /api/scan/{sid}/cancel                 (POST)
  /api/scan/{sid}/audit                  (GET event stream snapshot)
  /api/scan/{sid}/export/{fmt}           (GET sarif|json|csv|md|pdf|html)
  /api/scan/diff/{sid_a}/{sid_b}         (GET buckets)
  /api/finding/{fid}                     (GET / PATCH status / override)
  /api/finding/{fid}/notes               (POST add / GET list)
  /ws/scan/{sid}                         (WebSocket progress)
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import db
import diff as diff_mod
import exports
from orchestrator import AVAILABLE_MODULES, PROFILES, ScanOrchestrator
from report import ReportGenerator


app = FastAPI(
    title="CyberSyc",
    description="Cybersecurity vulnerability scanner & PoC report generator",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:8000", "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db.init_db()
orchestrator = ScanOrchestrator()
report_generator = ReportGenerator()


# ---------- request / response models ----------

class EngagementIn(BaseModel):
    client_name: str
    contract_id: Optional[str] = None
    in_scope_targets: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    rules_of_engagement: Optional[str] = None
    emergency_contact: Optional[str] = None
    tester_name: str
    tester_email: Optional[str] = None
    loa_text: Optional[str] = None  # raw LoA text — gets hashed
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    notes: Optional[str] = None


class ScanRequest(BaseModel):
    target_url: str
    engagement_id: Optional[str] = None
    profile: str = "standard"
    modules: Optional[list[str]] = None  # if None, profile decides


class FindingPatch(BaseModel):
    status: Optional[str] = None
    severity_override: Optional[str] = None
    severity_override_reason: Optional[str] = None
    confidence: Optional[str] = None


class NoteIn(BaseModel):
    body: str
    author: Optional[str] = None


# ---------- helpers ----------

def validate_url(url: str) -> str:
    if not url:
        raise HTTPException(400, "Target URL is required")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    p = urlparse(url)
    if not p.hostname:
        raise HTTPException(400, "Invalid URL: no hostname")
    blocked = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
    if p.hostname.lower() in blocked:
        raise HTTPException(400, "Scanning localhost / private addresses is not allowed")
    return url


def assert_in_scope(url: str, engagement_id: Optional[str]) -> None:
    """If an engagement is supplied, target host must be inside its scope."""
    if not engagement_id:
        return
    eng = db.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    in_scope = [s.lower() for s in (eng.get("in_scope_targets") or [])]
    out_scope = [s.lower() for s in (eng.get("out_of_scope") or [])]
    host = (urlparse(url).hostname or "").lower()
    if not host:
        raise HTTPException(400, "Invalid target host")
    matched = any(host == s or host.endswith("." + s) for s in in_scope)
    in_out = any(host == s or host.endswith("." + s) for s in out_scope)
    if in_out:
        raise HTTPException(400, f"Target {host} is in the engagement out-of-scope list")
    if in_scope and not matched:
        raise HTTPException(400, f"Target {host} is not in this engagement's scope")


# ---------- meta ----------

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "CyberSyc", "version": "1.1.0"}


@app.get("/api/profiles")
async def list_profiles():
    return {
        "profiles": {
            name: {
                "modules": modules,
                "description": _profile_blurb(name),
            }
            for name, modules in PROFILES.items()
        },
        "modules": list(AVAILABLE_MODULES.keys()),
    }


def _profile_blurb(name: str) -> str:
    return {
        "recon": "Read-only fingerprinting. No injection. Safe on production.",
        "standard": "Recon + the major injection families. The everyday default.",
        "deep": "Everything available, including rate-limit and access-control probes.",
    }.get(name, "")


# ---------- engagements ----------

@app.post("/api/engagements")
async def create_engagement(body: EngagementIn):
    eid = str(uuid.uuid4())
    loa_hash = (
        hashlib.sha256(body.loa_text.encode()).hexdigest()
        if body.loa_text else None
    )
    db.insert_engagement({
        "id": eid,
        "client_name": body.client_name,
        "contract_id": body.contract_id,
        "in_scope_targets": body.in_scope_targets,
        "out_of_scope": body.out_of_scope,
        "rules_of_engagement": body.rules_of_engagement,
        "emergency_contact": body.emergency_contact,
        "tester_name": body.tester_name,
        "tester_email": body.tester_email,
        "loa_hash": loa_hash,
        "window_start": body.window_start,
        "window_end": body.window_end,
        "notes": body.notes,
    })
    db.log_event("engagement_created", engagement_id=eid,
                 details={"client_name": body.client_name, "tester": body.tester_name})
    return db.get_engagement(eid)


@app.get("/api/engagements")
async def list_engagements():
    rows = db.list_engagements()
    out = []
    for e in rows:
        scans = db.list_scans(engagement_id=e["id"], limit=20)
        e["scan_count"] = len(scans)
        e["latest_scan"] = scans[0] if scans else None
        out.append(e)
    return out


@app.get("/api/engagements/{eid}")
async def get_engagement(eid: str):
    eng = db.get_engagement(eid)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    eng["scans"] = db.list_scans(engagement_id=eid, limit=200)
    return eng


@app.patch("/api/engagements/{eid}/status")
async def patch_engagement_status(eid: str, body: dict):
    status = body.get("status")
    if status not in ("active", "paused", "closed"):
        raise HTTPException(400, "Invalid status")
    if not db.get_engagement(eid):
        raise HTTPException(404, "Engagement not found")
    db.update_engagement_status(eid, status)
    db.log_event("engagement_status_change", engagement_id=eid, details={"status": status})
    return db.get_engagement(eid)


# ---------- scans ----------

@app.post("/api/scan")
async def start_scan(body: ScanRequest):
    target_url = validate_url(body.target_url)
    assert_in_scope(target_url, body.engagement_id)

    profile = body.profile if body.profile in PROFILES else "standard"
    chosen = body.modules or PROFILES[profile]
    valid = [m for m in chosen if m in AVAILABLE_MODULES]
    if not valid:
        raise HTTPException(400, "No valid scan modules selected")

    scan_id = orchestrator.create_scan(
        target_url, valid,
        engagement_id=body.engagement_id, profile=profile,
    )
    return {"scan_id": scan_id, "status": "pending", "target_url": target_url, "profile": profile}


@app.get("/api/scans")
async def list_scans(engagement_id: Optional[str] = None, limit: int = 50):
    rows = db.list_scans(engagement_id=engagement_id, limit=limit)
    return rows


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan = orchestrator.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan["status"] not in ("pending", "running"):
        raise HTTPException(400, f"Scan is {scan['status']}, cannot cancel")
    cancelled = orchestrator.cancel(scan_id)
    if not cancelled:
        # No live token — just mark cancelled directly
        from datetime import datetime, timezone
        db.update_scan(scan_id, status="cancelled",
                       cancelled_at=datetime.now(timezone.utc).isoformat())
    return {"scan_id": scan_id, "status": "cancelling"}


@app.get("/api/scan/{scan_id}/audit")
async def get_audit(scan_id: str):
    if not db.get_scan(scan_id):
        raise HTTPException(404, "Scan not found")
    return db.list_audit_events(scan_id=scan_id, limit=1000)


@app.get("/api/scan/diff/{older_id}/{newer_id}")
async def get_diff(older_id: str, newer_id: str):
    older = db.get_scan(older_id)
    newer = db.get_scan(newer_id)
    if not older or not newer:
        raise HTTPException(404, "Scan(s) not found")
    if older["target_url"] != newer["target_url"]:
        raise HTTPException(400, "Scans target different URLs")
    older_findings = db.list_findings_for_scan(older_id)
    newer_findings = db.list_findings_for_scan(newer_id)
    buckets = diff_mod.diff_findings(older_findings, newer_findings)
    return {
        "older": {"scan_id": older_id, "started_at": older["started_at"]},
        "newer": {"scan_id": newer_id, "started_at": newer["started_at"]},
        "summary": diff_mod.diff_summary(buckets),
        "buckets": buckets,
    }


# ---------- findings ----------

@app.get("/api/finding/{fid}")
async def get_finding(fid: str):
    f = db.get_finding(fid)
    if not f:
        raise HTTPException(404, "Finding not found")
    f["notes"] = db.list_notes(fid)
    return f


@app.patch("/api/finding/{fid}")
async def patch_finding(fid: str, body: FindingPatch):
    f = db.get_finding(fid)
    if not f:
        raise HTTPException(404, "Finding not found")

    fields: dict = {}
    if body.status is not None:
        if body.status not in (
            "new", "triaging", "confirmed",
            "false_positive", "accepted_risk", "fixed", "wont_fix",
        ):
            raise HTTPException(400, "Invalid status")
        fields["status"] = body.status

    if body.severity_override is not None:
        if body.severity_override not in ("critical", "high", "medium", "low", "info", ""):
            raise HTTPException(400, "Invalid severity_override")
        fields["severity_override"] = body.severity_override or None

    if body.severity_override_reason is not None:
        fields["severity_override_reason"] = body.severity_override_reason

    if body.confidence is not None:
        if body.confidence not in ("heuristic", "reflected", "executed", "operator_confirmed"):
            raise HTTPException(400, "Invalid confidence")
        fields["confidence"] = body.confidence

    if fields:
        db.update_finding(fid, **fields)
        db.log_event(
            "finding_patch",
            scan_id=f["scan_id"], finding_id=fid,
            details=fields,
        )
    out = db.get_finding(fid)
    out["notes"] = db.list_notes(fid)
    return out


@app.get("/api/finding/{fid}/notes")
async def list_finding_notes(fid: str):
    if not db.get_finding(fid):
        raise HTTPException(404, "Finding not found")
    return db.list_notes(fid)


@app.post("/api/finding/{fid}/notes")
async def add_finding_note(fid: str, body: NoteIn):
    if not db.get_finding(fid):
        raise HTTPException(404, "Finding not found")
    note_id = str(uuid.uuid4())
    db.add_note({
        "id": note_id, "finding_id": fid,
        "body": body.body, "author": body.author,
    })
    db.log_event("note_added", finding_id=fid, details={"note_id": note_id})
    return db.list_notes(fid)


# ---------- exports ----------

@app.get("/api/scan/{scan_id}/export/{fmt}")
async def export_scan(scan_id: str, fmt: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = db.list_findings_for_scan(scan_id)
    engagement = (
        db.get_engagement(scan["engagement_id"])
        if scan.get("engagement_id") else None
    )

    fmt = fmt.lower()
    short = scan_id[:8]

    if fmt == "json":
        import json as _json
        body = _json.dumps(
            exports.to_json(scan, findings, engagement),
            indent=2, default=str,
        )
        return Response(
            content=body, media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="cybersyc-{short}.json"'},
        )

    if fmt == "sarif":
        import json as _json
        body = _json.dumps(exports.to_sarif(scan, findings), indent=2, default=str)
        return Response(
            content=body, media_type="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="cybersyc-{short}.sarif"'},
        )

    if fmt == "csv":
        body = exports.to_csv(scan, findings)
        return Response(
            content=body, media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="cybersyc-{short}.csv"'},
        )

    if fmt in ("md", "markdown"):
        body = exports.to_markdown(scan, findings, engagement)
        return Response(
            content=body, media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="cybersyc-{short}.md"'},
        )

    if fmt in ("pdf", "html"):
        try:
            html = report_generator.generate_html(scan, findings, engagement)
            if fmt == "html":
                return Response(
                    content=html, media_type="text/html",
                    headers={"Content-Disposition": f'inline; filename="cybersyc-{short}.html"'},
                )
            try:
                from weasyprint import HTML as WeasyHTML
                pdf = WeasyHTML(string=html).write_pdf()
                return Response(
                    content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="cybersyc-{short}.pdf"'},
                )
            except ImportError:
                # No WeasyPrint — return printable HTML; client-side print-to-PDF
                return Response(
                    content=html, media_type="text/html",
                    headers={"Content-Disposition": f'inline; filename="cybersyc-{short}.html"'},
                )
        except Exception as e:
            raise HTTPException(500, f"Report generation failed: {e}")

    raise HTTPException(400, f"Unknown format: {fmt}. Use sarif | json | csv | md | pdf | html")


# ---------- legacy alias ----------

@app.get("/api/report/{scan_id}/pdf")
async def legacy_pdf(scan_id: str):
    return await export_scan(scan_id, "pdf")


# ---------- websocket progress ----------

@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    if not db.get_scan(scan_id):
        await websocket.send_json({"type": "error", "message": "Scan not found"})
        await websocket.close()
        return
    try:
        await orchestrator.run_scan(scan_id, websocket)
    except WebSocketDisconnect:
        # Continue scan headless
        await orchestrator.run_scan(scan_id, websocket=None)
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": f"Scan failed: {e}"})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
