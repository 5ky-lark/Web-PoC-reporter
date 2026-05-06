"""
Report generator — renders a printable HTML report. WeasyPrint converts to PDF
when available; otherwise the HTML is served and the browser handles print-to-PDF.

Aesthetic: black ink on warm white, no purple gradient. Severity carries OKLCH
colour and a single-letter glyph. The engagement metadata block, in-scope list,
and tester identity are first-class. Per-page running watermark on the running
header with the target hostname and scan ID for tamper-resistance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


_SEVERITY_GLYPH = {
    "critical": "C", "high": "H", "medium": "M", "low": "L", "info": "i",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberSyc Report — {{ target_url }}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

@page {
  size: A4;
  margin: 22mm 18mm;
  @top-center {
    content: "CYBERSYC · {{ target_host }} · {{ scan_short }} · CONFIDENTIAL";
    font: 500 8pt 'JetBrains Mono', monospace;
    color: #6a6a72;
    letter-spacing: 0.02em;
  }
  @bottom-right {
    content: counter(page) " / " counter(pages);
    font: 500 8pt 'JetBrains Mono', monospace;
    color: #6a6a72;
  }
}

* { margin: 0; padding: 0; box-sizing: border-box; }

:root {
  --paper:    #fbfaf6;
  --ink:      #1a1a22;
  --ink-2:    #3d3d48;
  --ink-3:    #6a6a72;
  --rule:     #d8d6cf;
  --rule-2:   #ecebe5;

  --sev-c:    #c01b21;
  --sev-h:    #c46a1f;
  --sev-m:    #b08316;
  --sev-l:    #2c5fa3;
  --sev-i:    #6a6a72;

  --bg-c:     #faecec;
  --bg-h:     #f9eede;
  --bg-m:     #f6f0d4;
  --bg-l:     #e6edf6;
  --bg-i:     #ededed;
}

html, body {
  background: var(--paper);
  color: var(--ink);
  font: 400 10.5pt/1.55 'Inter', -apple-system, sans-serif;
  font-feature-settings: 'tnum';
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;
}

a { color: inherit; text-decoration: none; }
a:hover { text-decoration: underline; }

h1, h2, h3, h4 { font-weight: 600; letter-spacing: -0.005em; }

/* ---------- cover ---------- */
.cover {
  page-break-after: always;
  height: 100vh;
  display: flex;
  flex-direction: column;
  padding: 50pt 0 30pt;
}
.cover-rule {
  border-top: 1px solid var(--ink);
  margin-bottom: 20pt;
}
.cover-eyebrow {
  font: 500 9pt 'JetBrains Mono', monospace;
  letter-spacing: 0.04em;
  color: var(--ink-3);
  margin-bottom: 14pt;
}
.cover-title {
  font-size: 32pt;
  line-height: 1.05;
  font-weight: 600;
  margin-bottom: 8pt;
  letter-spacing: -0.02em;
}
.cover-subtitle {
  font-size: 14pt;
  font-weight: 400;
  color: var(--ink-2);
  margin-bottom: 30pt;
}
.cover-target {
  font: 500 13pt 'JetBrains Mono', monospace;
  border-top: 1px solid var(--rule);
  border-bottom: 1px solid var(--rule);
  padding: 12pt 0;
  margin: 24pt 0;
  word-break: break-all;
}
.cover-meta {
  margin-top: auto;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 4pt 24pt;
  font-size: 9.5pt;
  color: var(--ink-2);
}
.cover-meta dt { color: var(--ink-3); font-weight: 500; padding-top: 6pt; }
.cover-meta dd {
  font-family: 'JetBrains Mono', monospace;
  font-size: 9pt;
  color: var(--ink);
  padding-bottom: 6pt;
  border-bottom: 1px solid var(--rule-2);
}
.cover-confidential {
  margin-top: 20pt;
  font: 500 8.5pt 'JetBrains Mono', monospace;
  color: var(--ink-3);
}

/* ---------- common section ---------- */
section { page-break-inside: avoid; margin-top: 22pt; }
section.major { page-break-before: always; }

h2 {
  font-size: 18pt;
  letter-spacing: -0.015em;
  margin-bottom: 14pt;
  padding-bottom: 8pt;
  border-bottom: 1px solid var(--ink);
}
h3 {
  font-size: 13pt;
  margin: 18pt 0 8pt;
  letter-spacing: -0.01em;
}
h4 {
  font-size: 9pt;
  font-weight: 500;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--ink-3);
  margin: 14pt 0 6pt;
  font-family: 'JetBrains Mono', monospace;
}
p { margin-bottom: 8pt; max-width: 70ch; }

/* ---------- summary ---------- */
.summary-rows {
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 0;
  border-top: 1px solid var(--rule);
  margin: 12pt 0 18pt;
}
.summary-row {
  display: contents;
}
.summary-row > * {
  padding: 8pt 4pt;
  border-bottom: 1px solid var(--rule-2);
}
.summary-row .glyph {
  font: 500 11pt 'JetBrains Mono', monospace;
  width: 24pt;
  text-align: center;
}
.summary-row .label { font-weight: 500; }
.summary-row .count {
  font: 500 11pt 'JetBrains Mono', monospace;
  text-align: right;
}
.glyph-c { color: var(--sev-c); }
.glyph-h { color: var(--sev-h); }
.glyph-m { color: var(--sev-m); }
.glyph-l { color: var(--sev-l); }
.glyph-i { color: var(--sev-i); }

/* ---------- engagement block ---------- */
.kv {
  display: grid;
  grid-template-columns: 110pt 1fr;
  font-size: 10pt;
  margin-top: 8pt;
}
.kv dt {
  color: var(--ink-3);
  padding: 4pt 0;
  font-family: 'JetBrains Mono', monospace;
  font-size: 9pt;
}
.kv dd { padding: 4pt 0; }

ul.in-scope {
  list-style: none;
  font-family: 'JetBrains Mono', monospace;
  font-size: 9.5pt;
}
ul.in-scope li { padding: 2pt 0; }
ul.in-scope li::before { content: "▸ "; color: var(--ink-3); }

/* ---------- finding ---------- */
.finding {
  margin-top: 22pt;
  page-break-inside: avoid;
}
.finding-head {
  display: grid;
  grid-template-columns: auto auto 1fr auto;
  gap: 10pt;
  align-items: baseline;
  border-bottom: 1px solid var(--ink);
  padding-bottom: 8pt;
}
.fin-glyph {
  font: 600 13pt 'JetBrains Mono', monospace;
  width: 18pt;
  text-align: center;
}
.fin-id {
  font: 500 10pt 'JetBrains Mono', monospace;
  color: var(--ink-3);
}
.fin-title {
  font-size: 13pt;
  font-weight: 600;
  letter-spacing: -0.01em;
}
.fin-cvss {
  font: 500 10.5pt 'JetBrains Mono', monospace;
}
.fin-meta {
  display: flex;
  gap: 14pt;
  margin-top: 6pt;
  font: 500 9pt 'JetBrains Mono', monospace;
  color: var(--ink-3);
}
.fin-meta span strong { color: var(--ink); font-weight: 500; }

/* severity card row */
.fin.critical .fin-glyph { color: var(--sev-c); }
.fin.high .fin-glyph { color: var(--sev-h); }
.fin.medium .fin-glyph { color: var(--sev-m); }
.fin.low .fin-glyph { color: var(--sev-l); }
.fin.info .fin-glyph { color: var(--sev-i); }

/* code blocks */
pre {
  background: #f3f1ea;
  border: 1px solid var(--rule);
  border-radius: 3px;
  padding: 8pt 10pt;
  font: 400 8.5pt/1.55 'JetBrains Mono', monospace;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 6pt 0;
}
code.inline {
  font: 400 9.5pt 'JetBrains Mono', monospace;
  background: #f3f1ea;
  padding: 1pt 4pt;
  border-radius: 2px;
}

ol.poc {
  list-style: none;
  counter-reset: step;
  margin: 6pt 0;
}
ol.poc li {
  counter-increment: step;
  position: relative;
  padding: 4pt 0 4pt 22pt;
  font-size: 10pt;
}
ol.poc li::before {
  content: counter(step);
  position: absolute; left: 0; top: 4pt;
  width: 14pt; height: 14pt;
  font: 500 9pt 'JetBrains Mono', monospace;
  border: 1px solid var(--ink);
  border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
}

.remediation {
  border-left: 1px solid var(--ink);
  padding: 4pt 12pt;
  font-size: 10pt;
  color: var(--ink-2);
  margin: 6pt 0;
}

ul.refs {
  list-style: none;
  font: 400 9pt 'JetBrains Mono', monospace;
  margin: 6pt 0;
}
ul.refs li { padding: 2pt 0; word-break: break-all; }

/* summary table */
table.summary-table {
  width: 100%; border-collapse: collapse; margin-top: 8pt;
  font-size: 9.5pt;
}
table.summary-table th, table.summary-table td {
  text-align: left; padding: 6pt 6pt 6pt 0;
  border-bottom: 1px solid var(--rule-2);
}
table.summary-table th {
  font: 500 8.5pt 'JetBrains Mono', monospace;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--ink-3);
  border-bottom: 1px solid var(--ink);
}
table.summary-table td.sev {
  font: 500 9.5pt 'JetBrains Mono', monospace;
  width: 70pt;
}
table.summary-table .id-cell {
  font: 500 9pt 'JetBrains Mono', monospace;
  color: var(--ink-3);
  width: 90pt;
}
table.summary-table .cvss-cell {
  font: 500 9.5pt 'JetBrains Mono', monospace;
  text-align: right;
  width: 50pt;
}
.sev-c { color: var(--sev-c); }
.sev-h { color: var(--sev-h); }
.sev-m { color: var(--sev-m); }
.sev-l { color: var(--sev-l); }
.sev-i { color: var(--sev-i); }

footer.page-foot {
  margin-top: 50pt;
  padding-top: 10pt;
  border-top: 1px solid var(--rule);
  font: 400 8.5pt 'JetBrains Mono', monospace;
  color: var(--ink-3);
}
</style>
</head>
<body>

<!-- ============= COVER ============= -->
<div class="cover">
  <div class="cover-rule"></div>
  <div class="cover-eyebrow">CYBERSYC · SECURITY ASSESSMENT</div>
  <h1 class="cover-title">{{ engagement_or_default_title }}</h1>
  <div class="cover-subtitle">Findings, evidence, and reproducers from an authorized scan.</div>

  <div class="cover-target">{{ target_url }}</div>

  <dl class="cover-meta">
    {% if engagement %}
    <dt>Client</dt><dd>{{ engagement.client_name }}</dd>
    {% if engagement.contract_id %}<dt>Contract</dt><dd>{{ engagement.contract_id }}</dd>{% endif %}
    <dt>Tester</dt><dd>{{ engagement.tester_name }}{% if engagement.tester_email %} <{{ engagement.tester_email }}>{% endif %}</dd>
    {% if engagement.window_start %}<dt>Window</dt><dd>{{ engagement.window_start }} → {{ engagement.window_end or 'open' }}</dd>{% endif %}
    {% if engagement.loa_hash %}<dt>LoA SHA-256</dt><dd>{{ engagement.loa_hash[:24] }}…</dd>{% endif %}
    {% endif %}
    <dt>Scan ID</dt><dd>{{ scan_id }}</dd>
    <dt>Started</dt><dd>{{ scan.started_at }}</dd>
    {% if scan.completed_at %}<dt>Completed</dt><dd>{{ scan.completed_at }}</dd>{% endif %}
    <dt>Profile</dt><dd>{{ scan.profile }}</dd>
    <dt>Modules</dt><dd>{{ scan.modules_run | length }} run</dd>
  </dl>

  <div class="cover-confidential">CONFIDENTIAL — INTENDED RECIPIENT ONLY</div>
</div>

<!-- ============= EXECUTIVE SUMMARY ============= -->
<section class="major">
  <h2>Executive summary</h2>

  <p>
    On {{ scan_date }}, an authorized security assessment was performed against
    <code class="inline">{{ target_host }}</code>. The assessment ran
    {{ scan.modules_run | length }} module(s) under the
    <strong>{{ scan.profile }}</strong> profile and produced
    <strong>{{ total_findings }}</strong> finding(s).
  </p>

  <h4>By severity</h4>
  <div class="summary-rows">
    {% for sev, label in [('critical','Critical'),('high','High'),('medium','Medium'),('low','Low'),('info','Informational')] %}
    <div class="summary-row">
      <span class="glyph glyph-{{ sev[0] }}">{{ glyphs[sev] }}</span>
      <span class="label">{{ label }}</span>
      <span class="count">{{ summary[sev] or 0 }}</span>
    </div>
    {% endfor %}
  </div>

  {% if priority_findings %}
  <h4>Priority findings</h4>
  <ol style="padding-left: 20pt; font-size: 10pt;">
  {% for f in priority_findings %}
    <li><strong>{{ f.title }}</strong> &middot;
      <code class="inline">{{ f.tracking_id or f.id[:8] }}</code> &middot;
      CVSS {{ '%.1f'|format(f.cvss_score) }}
      ({{ f.severity | upper }})
    </li>
  {% endfor %}
  </ol>
  {% endif %}
</section>

<!-- ============= ENGAGEMENT ============= -->
{% if engagement %}
<section class="major">
  <h2>Engagement</h2>
  <dl class="kv">
    <dt>Client</dt><dd>{{ engagement.client_name }}</dd>
    {% if engagement.contract_id %}<dt>Contract</dt><dd>{{ engagement.contract_id }}</dd>{% endif %}
    <dt>Tester</dt><dd>{{ engagement.tester_name }}{% if engagement.tester_email %} &lt;{{ engagement.tester_email }}&gt;{% endif %}</dd>
    {% if engagement.window_start %}<dt>Window</dt><dd>{{ engagement.window_start }} → {{ engagement.window_end or 'open' }}</dd>{% endif %}
    {% if engagement.emergency_contact %}<dt>Emergency</dt><dd>{{ engagement.emergency_contact }}</dd>{% endif %}
    {% if engagement.loa_hash %}<dt>LoA SHA-256</dt><dd><code class="inline">{{ engagement.loa_hash }}</code></dd>{% endif %}
  </dl>

  {% if engagement.in_scope_targets %}
  <h4>In scope</h4>
  <ul class="in-scope">
    {% for t in engagement.in_scope_targets %}<li>{{ t }}</li>{% endfor %}
  </ul>
  {% endif %}

  {% if engagement.out_of_scope %}
  <h4>Out of scope</h4>
  <ul class="in-scope">
    {% for t in engagement.out_of_scope %}<li>{{ t }}</li>{% endfor %}
  </ul>
  {% endif %}

  {% if engagement.rules_of_engagement %}
  <h4>Rules of engagement</h4>
  <p style="white-space: pre-wrap;">{{ engagement.rules_of_engagement }}</p>
  {% endif %}
</section>
{% endif %}

<!-- ============= METHODOLOGY ============= -->
<section class="major">
  <h2>Methodology</h2>
  <p>The following automated scanning modules were executed against the target.</p>

  <table class="summary-table">
    <tr><th>Module</th><th>Description</th></tr>
    {% for m in scan.modules_run %}
    <tr>
      <td><code class="inline">{{ m }}</code></td>
      <td>{{ module_descriptions.get(m, m) }}</td>
    </tr>
    {% endfor %}
  </table>

  <p style="margin-top: 12pt; color: var(--ink-3); font-size: 9.5pt;">
    Automated scanners are heuristic. Findings flagged with confidence
    <code class="inline">heuristic</code> require manual verification before
    being treated as confirmed exploits. The reproducer block on each finding
    is intended to make that verification straightforward.
  </p>
</section>

<!-- ============= FINDINGS ============= -->
<section class="major">
  <h2>Findings</h2>

  {% for f in findings %}
  <div class="finding fin {{ f.severity }}">
    <div class="finding-head">
      <span class="fin-glyph">{{ glyphs[f.severity] }}</span>
      <span class="fin-id">{{ f.tracking_id or ('CYS-' + f.id[:6]) }}</span>
      <span class="fin-title">{{ f.title }}</span>
      <span class="fin-cvss">CVSS {{ '%.1f'|format(f.cvss_score or 0) }}</span>
    </div>
    <div class="fin-meta">
      <span><strong>Module</strong> {{ f.module }}</span>
      {% if f.cwe_id %}<span><strong>CWE</strong> {{ f.cwe_id }}</span>{% endif %}
      <span><strong>Confidence</strong> {{ f.confidence }}</span>
      {% if f.target_url and f.target_url != target_url %}
      <span><strong>Path</strong> {{ f.target_url }}</span>
      {% endif %}
    </div>

    {% if f.severity_override %}
    <div style="margin-top: 8pt; font-size: 9.5pt; color: var(--ink-3);">
      Severity overridden to <strong>{{ f.severity_override | upper }}</strong>
      by operator{% if f.severity_override_reason %} — {{ f.severity_override_reason }}{% endif %}.
    </div>
    {% endif %}

    {% if f.description %}
    <h4>Description</h4>
    <p>{{ f.description }}</p>
    {% endif %}

    {% if f.cvss_vector %}
    <h4>CVSS vector</h4>
    <pre>{{ f.cvss_vector }}</pre>
    {% endif %}

    {% if f.evidence_curl %}
    <h4>Reproducer</h4>
    <pre>{{ f.evidence_curl }}</pre>
    {% endif %}

    {% if f.evidence_request %}
    <h4>Request</h4>
    <pre>{{ f.evidence_request }}</pre>
    {% endif %}

    {% if f.evidence_response %}
    <h4>Response</h4>
    <pre>{{ f.evidence_response }}</pre>
    {% endif %}

    {% if f.evidence and not f.evidence_request %}
    <h4>Evidence</h4>
    <pre>{{ f.evidence }}</pre>
    {% endif %}

    {% if f.poc_steps %}
    <h4>Proof of concept</h4>
    <ol class="poc">
    {% for step in f.poc_steps %}<li>{{ step }}</li>{% endfor %}
    </ol>
    {% endif %}

    {% if f.remediation %}
    <h4>Remediation</h4>
    <div class="remediation">{{ f.remediation }}</div>
    {% endif %}

    {% if f.references %}
    <h4>References</h4>
    <ul class="refs">
    {% for r in f.references %}<li>{{ r }}</li>{% endfor %}
    </ul>
    {% endif %}
  </div>
  {% endfor %}
</section>

<!-- ============= SUMMARY TABLE ============= -->
<section class="major">
  <h2>Summary table</h2>
  <table class="summary-table">
    <tr>
      <th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Module</th>
    </tr>
    {% for f in findings %}
    <tr>
      <td class="id-cell">{{ f.tracking_id or ('CYS-' + f.id[:6]) }}</td>
      <td>{{ f.title }}</td>
      <td class="sev sev-{{ f.severity[0] }}">{{ glyphs[f.severity] }} {{ f.severity }}</td>
      <td class="cvss-cell">{{ '%.1f'|format(f.cvss_score or 0) }}</td>
      <td><code class="inline">{{ f.module }}</code></td>
    </tr>
    {% endfor %}
  </table>
</section>

<!-- ============= CVSS APPENDIX ============= -->
<section class="major">
  <h2>Appendix · CVSS scoring</h2>
  <table class="summary-table">
    <tr><th>Score</th><th>Severity</th><th>Description</th></tr>
    <tr><td><code class="inline">9.0–10.0</code></td><td class="sev sev-c">C critical</td><td>Immediate exploitation risk; full compromise plausible.</td></tr>
    <tr><td><code class="inline">7.0–8.9</code></td><td class="sev sev-h">H high</td><td>Significant; data breach or privilege escalation likely.</td></tr>
    <tr><td><code class="inline">4.0–6.9</code></td><td class="sev sev-m">M medium</td><td>Moderate; specific conditions required.</td></tr>
    <tr><td><code class="inline">0.1–3.9</code></td><td class="sev sev-l">L low</td><td>Minor; limited impact.</td></tr>
    <tr><td><code class="inline">0.0</code></td><td class="sev sev-i">i info</td><td>Informational; no direct security impact.</td></tr>
  </table>

  {% if errors %}
  <h3>Scan errors</h3>
  <ul class="refs">{% for e in errors %}<li>{{ e }}</li>{% endfor %}</ul>
  {% endif %}

  <footer class="page-foot">
    Generated by CyberSyc {{ version }} on {{ generated_at }}. Scan {{ scan_id }}.
  </footer>
</section>

</body>
</html>"""


MODULE_DESCRIPTIONS = {
    "crawler": "Site discovery & attack-surface crawling",
    "headers": "HTTP security headers analysis",
    "ssl": "SSL/TLS configuration assessment",
    "ports": "Port scanning & service detection",
    "tech": "Technology fingerprinting",
    "xss": "Cross-site scripting (XSS)",
    "sqli": "SQL injection",
    "cmdi": "OS command injection",
    "pathtraversal": "Path traversal / LFI",
    "cors": "CORS misconfiguration",
    "clickjack": "Clickjacking protection",
    "session": "Session & cookie security",
    "redirect": "Open redirect",
    "ratelimit": "Rate-limit & abuse",
    "accesscontrol": "Access control & admin exposure",
    "apisecurity": "API security & exposure",
    "cve": "Known CVE lookup",
}


class ReportGenerator:
    """Generates reports from scan dicts + finding dicts (DB-backed)."""

    def generate_html(
        self,
        scan: dict,
        findings: list[dict],
        engagement: Optional[dict] = None,
    ) -> str:
        from jinja2 import Template
        from urllib.parse import urlparse

        sorted_findings = sorted(
            findings,
            key=lambda f: (
                _SEVERITY_ORDER.get(f.get("severity"), 5),
                -float(f.get("cvss_score") or 0),
            ),
        )
        priority = [
            f for f in sorted_findings
            if f.get("severity") in ("critical", "high")
        ][:8]

        target_url = scan.get("target_url") or ""
        target_host = (urlparse(target_url).hostname or "").lower() or "unknown"

        title = (
            f"Assessment of {target_host}"
            if not engagement else
            f"{engagement['client_name']} — {target_host}"
        )

        return Template(REPORT_TEMPLATE).render(
            scan=scan,
            scan_id=scan.get("id", ""),
            scan_short=str(scan.get("id", ""))[:8],
            target_url=target_url,
            target_host=target_host,
            scan_date=(scan.get("started_at") or "")[:10],
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            version="1.1.0",
            engagement=engagement,
            engagement_or_default_title=title,
            findings=sorted_findings,
            total_findings=len(sorted_findings),
            summary=scan.get("summary") or {},
            priority_findings=priority,
            module_descriptions=MODULE_DESCRIPTIONS,
            errors=scan.get("errors") or [],
            glyphs=_SEVERITY_GLYPH,
        )

    def generate_pdf(
        self,
        scan: dict,
        findings: list[dict],
        engagement: Optional[dict] = None,
    ) -> bytes:
        html = self.generate_html(scan, findings, engagement)
        try:
            from weasyprint import HTML
            return HTML(string=html).write_pdf()
        except ImportError:
            return html.encode("utf-8")
