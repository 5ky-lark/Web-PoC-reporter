"""
Shared parameter extraction and injection utilities.
Used by all injection scanners (XSS, SQLi, CMDi, Path Traversal, Redirect).
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def extract_params(url: str, body: str = "") -> list[dict]:
    """Extract testable parameters from URL query string and HTML forms."""
    params = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    for name in query_params:
        params.append({"name": name, "url": url})

    if body:
        form_inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.I)
        for name in set(form_inputs):
            if name not in query_params:
                sep = "&" if parsed.query else "?"
                params.append({"name": name, "url": f"{url}{sep}{name}=test"})

    return params


def inject_param(url: str, param: str, value: str) -> str:
    """Inject a value into a URL parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
