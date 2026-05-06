"""
CVSS 3.1 base-score calculator + severity derivation.

The whole point: severity is *derived* from a CVSS vector, never asserted alongside
an inconsistent score (the bug in the old scanners where Severity.HIGH was claimed
with cvss_score=6.1 — which is medium per the official map).

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
import re
from typing import Optional

# Metric weights for CVSS 3.1 base score
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}     # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                            # Attack Complexity
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}               # Privileges Required, Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}               # Privileges Required, Scope Changed
_UI = {"N": 0.85, "R": 0.62}                            # User Interaction
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}                 # C/I/A impact metrics


_VECTOR_RE = re.compile(
    r"^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
)


def parse_vector(vector: str) -> Optional[dict]:
    """Parse a CVSS 3.1 vector string. Returns metrics dict or None on failure."""
    if not vector or not _VECTOR_RE.match(vector):
        return None
    parts = vector.split("/")
    out: dict[str, str] = {}
    for p in parts[1:]:
        if ":" in p:
            k, v = p.split(":", 1)
            out[k] = v
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(out):
        return None
    return out


def base_score(vector: str) -> float:
    """Compute CVSS 3.1 base score from vector. Returns 0.0 on parse failure."""
    m = parse_vector(vector)
    if not m:
        return 0.0
    scope_changed = m["S"] == "C"
    isc_base = 1 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))

    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    pr_table = _PR_C if scope_changed else _PR_U
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]

    if impact <= 0:
        return 0.0

    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)

    return round(math.ceil(raw * 10) / 10, 1)


def severity_from_score(score: float) -> str:
    """Map CVSS 3.1 score to severity. NIST/FIRST official ranges."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def derive(vector: str, fallback_score: float = 0.0) -> tuple[float, str]:
    """
    Single source of truth: vector -> (score, severity).
    If vector is invalid, fall back to the explicit score.
    """
    score = base_score(vector)
    if score == 0.0 and fallback_score > 0:
        score = fallback_score
    return score, severity_from_score(score)


# Common CVSS vectors used across the scanners — single source for consistency.
# Looking these up here means a scanner says "VECTOR_XSS_REFLECTED" not raw numbers.
VECTORS = {
    # Reflected XSS, requires user interaction, scope changed (browser context)
    "xss_reflected":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",   # 6.1 medium
    "xss_stored":      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",   # 8.7 high
    "sqli_error":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # 9.8 critical
    "sqli_blind":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # 9.1 critical
    "cmdi":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # 9.8 critical
    "path_traversal":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # 9.1 critical
    "open_redirect":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",   # 6.1 medium
    "cors_reflect":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",   # 7.4 high
    "cors_reflect_creds":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", # 8.0 high
    "cors_wildcard_creds":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",# 7.4 high
    "cors_null":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",   # 5.4 medium
    "missing_csp":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",   # 6.1 medium
    "missing_hsts":    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",   # 4.2 medium
    "missing_xfo":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",   # 4.3 medium
    "missing_xcto":    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",   # 3.1 low
    "missing_referrer":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",   # 3.1 low
    "missing_permissions":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",# 2.6 low
    "info_disclosure": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",   # 3.1 low
    "clickjack":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",   # 4.3 medium
    "ssl_weak":        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",   # 7.4 high
}


def vector(name: str) -> str:
    """Get a named CVSS vector. Falls back to empty string."""
    return VECTORS.get(name, "")
