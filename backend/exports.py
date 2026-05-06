"""
Multi-format exports: SARIF 2.1.0, JSON, Markdown, CSV.

These are the deliverables a real engagement actually hands off:
  - SARIF for the dev team's GitHub Security tab
  - JSON for raw automation
  - Markdown for git-versioned engagement repos
  - CSV for triage spreadsheets
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any


# -------- SARIF 2.1.0 --------

_SEVERITY_TO_SARIF = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "none",
}


def to_sarif(scan: dict, findings: list[dict]) -> dict:
    """SARIF 2.1.0 SchemaURI: https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rule_id = f.get("cwe_id") or f.get("module") or "CYS-UNKNOWN"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": (f.get("cwe_name") or f.get("module") or rule_id).replace(" ", ""),
                "shortDescription": {"text": f.get("cwe_name") or f.get("title", "")},
                "fullDescription": {"text": f.get("description") or f.get("title", "")},
                "helpUri": (f.get("references") or [""])[0] or
                           f"https://cwe.mitre.org/data/definitions/{rule_id.replace('CWE-', '')}.html",
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF.get(f.get("severity", "info"), "none"),
                },
                "properties": {
                    "security-severity": str(f.get("cvss_score") or 0),
                    "tags": ["security", f.get("module", "")],
                },
            }

        loc_uri = f.get("target_url") or scan.get("target_url", "")
        results.append({
            "ruleId": rule_id,
            "level": _SEVERITY_TO_SARIF.get(f.get("severity", "info"), "none"),
            "message": {"text": f.get("title", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": loc_uri},
                },
            }],
            "partialFingerprints": {
                "cybersycFingerprint/v1": f.get("fingerprint", ""),
            },
            "properties": {
                "tracking_id": f.get("tracking_id"),
                "cvss_score": f.get("cvss_score"),
                "cvss_vector": f.get("cvss_vector"),
                "confidence": f.get("confidence"),
                "status": f.get("status"),
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CyberSyc",
                    "version": "1.1.0",
                    "informationUri": "https://github.com/cybersyc/cybersyc",
                    "rules": list(rules.values()),
                }
            },
            "invocations": [{
                "executionSuccessful": scan.get("status") == "completed",
                "startTimeUtc": scan.get("started_at"),
                "endTimeUtc": scan.get("completed_at"),
            }],
            "results": results,
            "properties": {
                "scan_id": scan.get("id"),
                "target_url": scan.get("target_url"),
                "modules_run": scan.get("modules_run"),
            },
        }],
    }


# -------- JSON (full dump) --------

def to_json(scan: dict, findings: list[dict], engagement: dict | None = None) -> dict:
    return {
        "scan": scan,
        "engagement": engagement,
        "findings": findings,
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }


# -------- CSV (triage spreadsheet) --------

_CSV_FIELDS = [
    "tracking_id", "severity", "cvss_score", "title", "module",
    "cwe_id", "target_url", "status", "confidence", "discovered_at",
]


def to_csv(scan: dict, findings: list[dict]) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(_CSV_FIELDS)
    for f in findings:
        w.writerow([f.get(k, "") for k in _CSV_FIELDS])
    return out.getvalue()


# -------- Markdown (git-versioned report) --------

def to_markdown(
    scan: dict,
    findings: list[dict],
    engagement: dict | None = None,
) -> str:
    lines: list[str] = []
    target = scan.get("target_url", "")

    # Header
    lines.append(f"# CyberSyc Report")
    lines.append("")
    lines.append(f"**Target**: `{target}`  ")
    lines.append(f"**Scan ID**: `{scan.get('id', '')}`  ")
    lines.append(f"**Started**: {scan.get('started_at', '')}  ")
    lines.append(f"**Completed**: {scan.get('completed_at', '')}  ")
    if engagement:
        lines.append(f"**Client**: {engagement.get('client_name', '')}  ")
        lines.append(f"**Tester**: {engagement.get('tester_name', '')}  ")
    lines.append("")

    # Summary
    summary = scan.get("summary") or {}
    total = sum(int(v or 0) for v in summary.values())
    lines.append("## Summary")
    lines.append("")
    lines.append(f"**Total findings**: {total}")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {sev} | {summary.get(sev, 0)} |")
    lines.append("")

    # Findings
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings, key=lambda f: (severity_order.get(f.get("severity"), 5), -float(f.get("cvss_score") or 0))
    )

    lines.append("## Findings")
    lines.append("")
    for i, f in enumerate(sorted_findings, 1):
        lines.append(f"### {i}. {f.get('title', 'Untitled')}")
        lines.append("")
        lines.append(f"- **ID**: `{f.get('tracking_id', '')}`")
        lines.append(f"- **Severity**: `{f.get('severity', '').upper()}` (CVSS {f.get('cvss_score', 0)})")
        if f.get("cvss_vector"):
            lines.append(f"- **CVSS Vector**: `{f['cvss_vector']}`")
        if f.get("cwe_id"):
            lines.append(f"- **CWE**: {f['cwe_id']} {f.get('cwe_name', '')}")
        lines.append(f"- **Module**: {f.get('module', '')}")
        lines.append(f"- **Confidence**: {f.get('confidence', 'heuristic')}")
        if f.get("target_url"):
            lines.append(f"- **Target**: `{f['target_url']}`")
        lines.append("")

        if f.get("description"):
            lines.append("#### Description")
            lines.append("")
            lines.append(f["description"])
            lines.append("")

        if f.get("evidence_request"):
            lines.append("#### Reproducer")
            lines.append("")
            if f.get("evidence_curl"):
                lines.append("```bash")
                lines.append(f["evidence_curl"])
                lines.append("```")
                lines.append("")
            lines.append("**Request**")
            lines.append("")
            lines.append("```http")
            lines.append(f["evidence_request"])
            lines.append("```")
            lines.append("")
            if f.get("evidence_response"):
                lines.append("**Response**")
                lines.append("")
                lines.append("```http")
                lines.append(f["evidence_response"])
                lines.append("```")
                lines.append("")

        if f.get("evidence") and not f.get("evidence_request"):
            lines.append("#### Evidence")
            lines.append("")
            lines.append("```")
            lines.append(f["evidence"])
            lines.append("```")
            lines.append("")

        if f.get("poc_steps"):
            lines.append("#### Proof of Concept")
            lines.append("")
            for step in f["poc_steps"]:
                lines.append(f"1. {step}")
            lines.append("")

        if f.get("remediation"):
            lines.append("#### Remediation")
            lines.append("")
            lines.append(f["remediation"])
            lines.append("")

        refs = f.get("references") or []
        if refs:
            lines.append("#### References")
            lines.append("")
            for r in refs:
                lines.append(f"- {r}")
            lines.append("")

    return "\n".join(lines)
