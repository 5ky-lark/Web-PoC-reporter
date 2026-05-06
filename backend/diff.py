"""
Scan diff: compare findings between two scans of the same target.

Bucketing rules:
  new        — fingerprint exists only in the newer scan
  fixed      — fingerprint exists only in the older scan
  reopened   — same fingerprint, older scan finding had status='fixed'
  regressed  — severity got worse (older was lower-severity)
  improved   — severity got better
  unchanged  — same fingerprint, same severity
"""

from __future__ import annotations

from typing import Iterable


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _rank(sev: str) -> int:
    return _SEVERITY_RANK.get(sev or "info", 0)


def diff_findings(
    older: Iterable[dict], newer: Iterable[dict]
) -> dict:
    """Return diff buckets keyed by category. Each bucket holds Finding dicts."""
    older_by_fp: dict[str, dict] = {}
    for f in older:
        fp = f.get("fingerprint")
        if fp:
            older_by_fp[fp] = f

    newer_by_fp: dict[str, dict] = {}
    for f in newer:
        fp = f.get("fingerprint")
        if fp:
            newer_by_fp[fp] = f

    buckets = {
        "new": [],
        "fixed": [],
        "reopened": [],
        "regressed": [],
        "improved": [],
        "unchanged": [],
    }

    for fp, nf in newer_by_fp.items():
        of = older_by_fp.get(fp)
        if of is None:
            buckets["new"].append(nf)
            continue
        prev_status = of.get("status") or "new"
        if prev_status == "fixed":
            buckets["reopened"].append(nf)
            continue
        old_rank = _rank(of.get("severity"))
        new_rank = _rank(nf.get("severity"))
        if new_rank > old_rank:
            buckets["regressed"].append({**nf, "previous_severity": of.get("severity")})
        elif new_rank < old_rank:
            buckets["improved"].append({**nf, "previous_severity": of.get("severity")})
        else:
            buckets["unchanged"].append(nf)

    for fp, of in older_by_fp.items():
        if fp not in newer_by_fp:
            buckets["fixed"].append(of)

    return buckets


def diff_summary(buckets: dict) -> dict:
    """Counts only — for headlining the report."""
    return {k: len(v) for k, v in buckets.items()}
