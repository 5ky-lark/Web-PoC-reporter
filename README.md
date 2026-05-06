# Web-PoC-reporter

Operator-grade web vulnerability scanner and PoC reporter with reproducible evidence.

This project combines:
- A **FastAPI backend** for scanning orchestration, persistence, exports, and report generation
- A **vanilla JS + Vite frontend** for engagement management, scan execution, and triage
- A **SQLite data layer** for engagement history, findings workflow, notes, and audit trail

---

## What It Does

- Runs multi-module web security scans (crawler, headers, SSL, CORS, XSS, SQLi, command injection, path traversal, redirect, etc.)
- Streams real-time progress via WebSocket
- Stores scans, findings, notes, and audit events in SQLite
- Captures reproducible evidence for findings:
  - raw HTTP request
  - raw HTTP response
  - curl command
- Supports finding workflow statuses (`new`, `triaging`, `confirmed`, `false_positive`, `accepted_risk`, `fixed`, `wont_fix`)
- Supports severity override with rationale
- Compares scans (diff) into buckets (`new`, `fixed`, `reopened`, `regressed`, `improved`, `unchanged`)
- Exports in multiple formats:
  - SARIF 2.1.0
  - JSON
  - CSV
  - Markdown
  - PDF/HTML report

---

## Architecture

### Backend (`backend/`)

Core modules:
- `main.py` - FastAPI routes and API entrypoint
- `orchestrator.py` - staged scan pipeline + cancellation control
- `db.py` - SQLite schema + CRUD helpers
- `cvss.py` - CVSS 3.1 score/severity derivation
- `throttle.py` - per-host throttling + cancellation token + raw HTTP capture helpers
- `exports.py` - SARIF/JSON/CSV/Markdown exporters
- `diff.py` - scan comparison engine
- `report.py` - HTML/PDF report renderer
- `scanners/` - all scanner modules

### Frontend (`frontend/`)

- `index.html` - app shell
- `css/index.css` - design system and layout
- `js/main.js` - app bootstrap + route/view switching
- `js/engagement.js` - engagement UI flow
- `js/scanner.js` - scan run/progress/kill workflow
- `js/triage.js` - findings table, drawer, notes, workflow actions
- `js/api.js` - backend API client

---

## API Surface (High-Level)

- `GET /api/health`
- `GET /api/profiles`
- `POST /api/engagements`
- `GET /api/engagements`
- `GET /api/engagements/{eid}`
- `PATCH /api/engagements/{eid}/status`
- `POST /api/scan`
- `GET /api/scans`
- `GET /api/scan/{scan_id}`
- `POST /api/scan/{scan_id}/cancel`
- `GET /api/scan/{scan_id}/audit`
- `GET /api/scan/diff/{older_id}/{newer_id}`
- `GET /api/finding/{fid}`
- `PATCH /api/finding/{fid}`
- `GET /api/finding/{fid}/notes`
- `POST /api/finding/{fid}/notes`
- `GET /api/scan/{scan_id}/export/{fmt}`
- `WS /ws/scan/{scan_id}`

---

## Local Setup

### 1) Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Backend runs on: `http://localhost:8000`

### 2) Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on: `http://localhost:5173`

---

## Data Storage

- SQLite file is created in `backend/` (via `db.py`) on first run.
- It stores engagements, scans, findings, notes, and audit logs.

If you want a clean slate, stop the backend and delete the SQLite DB files in `backend/`.

---

## Notes

- This tool is for **authorized security testing only**.
- Scanning localhost/private addresses is blocked in API validation.
- PDF export uses WeasyPrint when available; otherwise HTML fallback is served for browser print-to-PDF.

---

## Project Status

Current state is a strong PoC-to-product transition baseline with:
- persistent data model
- reproducible PoC evidence
- triage workflow
- differential scan reporting
- multi-format export support

Future enhancements can include browser-assisted validation (Playwright), authenticated scan recipes, proxy chaining, and collaboration features.
