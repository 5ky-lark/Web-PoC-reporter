# CyberSyc PoC — Design Specification

## Overview

CyberSyc PoC is a single-user, local web application that performs semi-automated vulnerability assessments on target URLs and generates professional Proof of Concept (PoC) reports. The tool combines passive reconnaissance, active probing, and vulnerability detection into a unified scanning pipeline, presenting results in an interactive dashboard with professional PDF export capability.

## Goals

- Provide a one-click vulnerability scanning experience for cybersecurity professionals
- Generate professional-grade PoC reports suitable for client delivery
- Deliver real-time scan progress feedback via WebSocket
- Support both interactive in-app report viewing and PDF export
- Clean, light, premium UI aesthetic (no dark mode)

## Non-Goals

- Multi-user / authentication system
- Cloud deployment or SaaS features
- Persistent scan history / database
- Integration with third-party scanning tools (Nmap, Burp, etc.)

## Architecture

### Tech Stack

- **Frontend**: Vite + vanilla HTML/CSS/JavaScript
- **Backend**: Python FastAPI
- **Real-time**: WebSocket (FastAPI native)
- **PDF Generation**: WeasyPrint
- **HTTP Client**: httpx (async)
- **DNS/Network**: socket, ssl (stdlib) + dnspython

### System Diagram

```
Frontend (Vite, localhost:5173)
├── Scanner Page (URL input, module toggles, real-time progress)
├── Report Dashboard (interactive findings, charts, filters)
└── PDF Export (one-click professional PDF generation)
    │
    │ REST API + WebSocket
    ▼
Backend (FastAPI, localhost:8000)
├── POST /api/scan — Start a new scan
├── WS /ws/scan/{scan_id} — Real-time scan progress
├── GET /api/scan/{scan_id} — Get scan results
├── GET /api/report/{scan_id}/pdf — Download PDF report
│
├── Scan Orchestrator
│   ├── HeaderScanner
│   ├── SSLScanner
│   ├── PortScanner
│   ├── TechFingerprinter
│   ├── XSSScanner
│   ├── SQLiScanner
│   ├── CORSScanner
│   ├── ClickjackScanner
│   └── CVELookup
│
└── ReportGenerator (PDF via WeasyPrint)
```

### Communication Flow

1. User enters target URL and selects scan modules
2. Frontend sends POST /api/scan with target URL and module config
3. Backend creates scan job, returns scan_id
4. Frontend connects to WS /ws/scan/{scan_id}
5. Backend runs each scan module sequentially, sends progress updates via WebSocket
6. Each module sends: module name, status (running/complete/error), progress %, findings
7. On completion, backend sends final results payload
8. Frontend renders interactive report dashboard
9. User can click "Export PDF" which calls GET /api/report/{scan_id}/pdf

## Scan Modules

### 1. HTTP Headers Scanner (`HeaderScanner`)

**Purpose**: Check for presence and configuration of security headers.

**Checks**:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- Cache-Control for sensitive pages
- Server header information disclosure

**Severity Logic**:
- Missing CSP → High
- Missing HSTS → Medium
- Missing X-Frame-Options → Medium
- Server version disclosure → Low

### 2. SSL/TLS Scanner (`SSLScanner`)

**Purpose**: Assess SSL/TLS configuration and certificate health.

**Checks**:
- Certificate validity and expiration
- Certificate chain completeness
- Protocol versions supported (TLS 1.0, 1.1, 1.2, 1.3)
- Weak cipher suites
- HSTS preload status
- Certificate subject / SAN mismatch

**Severity Logic**:
- Expired certificate → Critical
- TLS 1.0/1.1 enabled → High
- Weak ciphers → High
- Certificate expiring within 30 days → Medium

### 3. Port Scanner (`PortScanner`)

**Purpose**: Discover open ports and running services on the target.

**Checks**:
- Top 100 common ports (TCP connect scan)
- Service banner grabbing
- Identification of unnecessary exposed services

**Severity Logic**:
- Database ports open (3306, 5432, 27017) → High
- Admin panels (8080, 8443) → Medium
- Standard web ports (80, 443) → Info

### 4. Technology Fingerprinter (`TechFingerprinter`)

**Purpose**: Identify server software, frameworks, and CMS.

**Checks**:
- Server response headers (Server, X-Powered-By)
- HTML meta tags and generator tags
- Known file paths (/wp-admin, /wp-login.php, etc.)
- JavaScript library detection
- Cookie naming conventions

**Severity Logic**:
- Outdated software version detected → High
- Technology version disclosure → Low
- Technology detected (no version) → Info

### 5. XSS Scanner (`XSSScanner`)

**Purpose**: Detect reflected Cross-Site Scripting vulnerabilities.

**Checks**:
- Parameter discovery from forms and URL parameters
- Reflection testing with benign probes
- Context-aware payload testing (HTML, attribute, JavaScript contexts)
- Basic DOM-based XSS patterns

**Payloads** (safe, detection-only):
```
<script>alert(1)</script>
"><img src=x onerror=alert(1)>
javascript:alert(1)
'-alert(1)-'
```

**Severity Logic**:
- Reflected XSS confirmed → High
- Potential XSS (unescaped reflection) → Medium

### 6. SQL Injection Scanner (`SQLiScanner`)

**Purpose**: Detect SQL injection vulnerabilities.

**Checks**:
- Error-based detection (single quote, double quote injection)
- Time-based blind detection (SLEEP/WAITFOR payloads)
- Boolean-based blind detection
- Common SQL error pattern matching

**Payloads**:
```
' OR '1'='1
" OR "1"="1
' WAITFOR DELAY '0:0:5'--
1 AND 1=1
1 AND 1=2
```

**Severity Logic**:
- Confirmed SQL injection → Critical
- SQL error message disclosed → High
- Potential blind SQLi → High

### 7. CORS Scanner (`CORSScanner`)

**Purpose**: Detect Cross-Origin Resource Sharing misconfigurations.

**Checks**:
- Origin reflection (echoes back arbitrary origins)
- Wildcard Access-Control-Allow-Origin with credentials
- Null origin acceptance
- Subdomain wildcard matching
- Pre-flight request handling

**Severity Logic**:
- Origin reflection with credentials → Critical
- Wildcard with credentials → High
- Null origin accepted → Medium

### 8. Clickjacking Scanner (`ClickjackScanner`)

**Purpose**: Check for clickjacking protection.

**Checks**:
- X-Frame-Options header presence and value
- CSP frame-ancestors directive
- JavaScript frame-busting code detection

**Severity Logic**:
- No protection at all → Medium
- Weak protection (JS only) → Low

### 9. CVE Lookup (`CVELookup`)

**Purpose**: Match detected software versions against known CVEs.

**Checks**:
- Query detected technology + version against a local CVE dataset
- Check for critical/high-severity known vulnerabilities
- Provide CVE IDs, descriptions, and CVSS scores

**Severity Logic**: Inherits from CVE CVSS score

## Finding Data Model

Every finding from every module conforms to this structure:

```python
class Finding:
    id: str                    # Unique finding ID (uuid)
    title: str                 # "Missing Content-Security-Policy Header"
    module: str                # "headers", "ssl", "xss", etc.
    severity: str              # "critical", "high", "medium", "low", "info"
    cvss_score: float          # 0.0 - 10.0
    cvss_vector: str           # "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cwe_id: str                # "CWE-79"
    cwe_name: str              # "Improper Neutralization of Input..."
    description: str           # Detailed description of the vulnerability
    evidence: str              # Raw evidence (headers, response snippets, etc.)
    poc_steps: list[str]       # Step-by-step reproduction instructions
    remediation: str           # How to fix it
    references: list[str]      # URLs to relevant documentation
```

## Frontend Design

### Visual Style

- **Theme**: Light mode only. White backgrounds, subtle gray borders (#f0f0f0)
- **Typography**: Inter font family (Google Fonts)
- **Accent Colors**:
  - Critical: #DC2626 (red-600)
  - High: #EA580C (orange-600)
  - Medium: #CA8A04 (yellow-600)
  - Low: #2563EB (blue-600)
  - Info: #6B7280 (gray-500)
- **Cards**: White with subtle box-shadow, 8px border-radius
- **Layout**: Max-width 1200px, centered, generous whitespace

### Scanner Page

- Clean top nav with "CyberSyc PoC" branding
- Large centered URL input field with "Start Scan" button
- Module toggles (checkboxes to enable/disable specific scan modules)
- "Authorization Confirmation" checkbox: "I have authorization to scan this target"
- Real-time scan progress:
  - Overall progress bar
  - Per-module progress indicators with status icons (⏳ pending, 🔄 running, ✅ complete, ❌ error)
  - Live findings feed (new findings animate in as discovered)

### Report Dashboard

- Summary stats bar: Total findings count by severity (colored badges)
- Severity distribution donut chart (using Chart.js or vanilla SVG)
- Filterable/sortable findings list
- Each finding is an expandable card showing:
  - Severity badge + CVSS score
  - Title and module source
  - Description (collapsed by default)
  - Evidence (code block)
  - PoC Steps (numbered list)
  - Remediation (highlighted box)
  - CWE/CVE references (links)

### PDF Export

- "Export PDF" button in report dashboard header
- Generates via backend (WeasyPrint)
- Professional layout with:
  - Cover page with branding, target URL, date
  - Table of contents
  - Executive summary with severity chart
  - Detailed findings (same structure as web view)
  - Summary table
  - Appendices

## API Endpoints

```
POST   /api/scan                    — Start new scan
  Body: { "target_url": "https://example.com", "modules": ["headers", "ssl", ...] }
  Response: { "scan_id": "uuid", "status": "started" }

GET    /api/scan/{scan_id}          — Get scan results
  Response: { "scan_id": "...", "status": "completed", "findings": [...], "summary": {...} }

GET    /api/report/{scan_id}/pdf    — Download PDF report
  Response: application/pdf

WS     /ws/scan/{scan_id}           — Real-time scan progress
  Messages: { "module": "headers", "status": "running", "progress": 50, "findings": [...] }
```

## Error Handling

- Invalid URL → 400 with descriptive error
- Target unreachable → Scan completes with error finding for that module
- Module crash → Other modules continue, error logged as info finding
- WebSocket disconnect → Scan continues, results available via GET endpoint

## Security Considerations

- Authorization checkbox required before scanning
- Disclaimer on UI: "Only scan targets you have explicit authorization to test"
- Rate limiting on scan requests (1 concurrent scan)
- No credentials or sensitive data stored
- All scans are stateless (in-memory only, lost on server restart)
