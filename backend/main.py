"""
FastAPI entry point — scans, findings, exports, diff, audit.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import db
import diff as diff_mod
import exports
from orchestrator import AVAILABLE_MODULES, PROFILES, ScanOrchestrator
from report import ReportGenerator


app = FastAPI(
    title="CyberSyc",
    description="Cybersecurity vulnerability scanner & PoC report generator",
    version="1.1.1",
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


class ScanRequest(BaseModel):
    target_url: str
    profile: str = "standard"
    modules: Optional[list[str]] = None


class FindingPatch(BaseModel):
    status: Optional[str] = None
    severity_override: Optional[str] = None
    severity_override_reason: Optional[str] = None
    confidence: Optional[str] = None


class NoteIn(BaseModel):
    body: str
    author: Optional[str] = None


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


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "CyberSyc", "version": "1.1.1"}


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


@app.post("/api/scan")
async def start_scan(body: ScanRequest):
    target_url = validate_url(body.target_url)

    profile = body.profile if body.profile in PROFILES else "standard"
    chosen = body.modules or PROFILES[profile]
    valid = [m for m in chosen if m in AVAILABLE_MODULES]
    if not valid:
        raise HTTPException(400, "No valid scan modules selected")

    scan_id = orchestrator.create_scan(target_url, valid, profile=profile)
    return {"scan_id": scan_id, "status": "pending", "target_url": target_url, "profile": profile}


@app.get("/api/scans")
async def list_scans(limit: int = 50):
    return db.list_scans(limit=limit)


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
    import uuid
    note_id = str(uuid.uuid4())
    db.add_note({
        "id": note_id, "finding_id": fid,
        "body": body.body, "author": body.author,
    })
    db.log_event("note_added", finding_id=fid, details={"note_id": note_id})
    return db.list_notes(fid)


@app.get("/api/scan/{scan_id}/export/{fmt}")
async def export_scan(scan_id: str, fmt: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = db.list_findings_for_scan(scan_id)

    fmt = fmt.lower()
    short = scan_id[:8]

    if fmt == "json":
        import json as _json
        body = _json.dumps(exports.to_json(scan, findings, None), indent=2, default=str)
        return Response(content=body, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="cybersyc-{short}.json"'})

    if fmt == "sarif":
        import json as _json
        body = _json.dumps(exports.to_sarif(scan, findings), indent=2, default=str)
        return Response(content=body, media_type="application/sarif+json", headers={"Content-Disposition": f'attachment; filename="cybersyc-{short}.sarif"'})

    if fmt == "csv":
        body = exports.to_csv(scan, findings)
        return Response(content=body, media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="cybersyc-{short}.csv"'})

    if fmt in ("md", "markdown"):
        body = exports.to_markdown(scan, findings, None)
        return Response(content=body, media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="cybersyc-{short}.md"'})

    if fmt in ("pdf", "html"):
        try:
            html = report_generator.generate_html(scan, findings, None)
            if fmt == "html":
                return Response(content=html, media_type="text/html", headers={"Content-Disposition": f'inline; filename="cybersyc-{short}.html"'})
            try:
                from weasyprint import HTML as WeasyHTML
                pdf = WeasyHTML(string=html).write_pdf()
                return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="cybersyc-{short}.pdf"'})
            except Exception as weasy_err:
                # Graceful degradation for Windows/Linux hosts missing cairo/pango libs:
                # return printable HTML instead of failing the export endpoint.
                print(f"[export] PDF fallback to HTML for scan {scan_id}: {weasy_err}")
                return Response(content=html, media_type="text/html", headers={"Content-Disposition": f'inline; filename="cybersyc-{short}.html"'})
        except Exception as e:
            raise HTTPException(500, f"Report generation failed: {e}")

    raise HTTPException(400, f"Unknown format: {fmt}. Use sarif | json | csv | md | pdf | html")


@app.get("/api/report/{scan_id}/pdf")
async def legacy_pdf(scan_id: str):
    return await export_scan(scan_id, "pdf")


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

