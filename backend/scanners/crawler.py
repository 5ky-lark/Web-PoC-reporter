"""
Site Crawler — Discovers attack surface by crawling the target site.
Extracts URLs, forms, and injectable parameters for use by injection scanners.
"""

import asyncio
import re
from collections import deque
from urllib.parse import urlparse, urljoin, parse_qs

import httpx

from scanners.base import BaseScanner, Finding, Severity
from scanners.params import extract_params
from pydantic import BaseModel, Field


class CrawlResult(BaseModel):
    """Results from site crawling."""
    urls: list[str] = Field(default_factory=list)
    params: list[dict] = Field(default_factory=list)
    forms: list[dict] = Field(default_factory=list)
    pages_crawled: int = 0


class CrawlerScanner(BaseScanner):
    name = "crawler"
    description = "Site Discovery & Crawling"

    MAX_PAGES = 50
    MAX_DEPTH = 3
    DELAY = 0.05  # 50ms between requests

    def __init__(self):
        self.crawl_result = CrawlResult()

    async def scan(self, target_url: str) -> list[Finding]:
        findings = []
        visited = set()
        queue = deque([(target_url, 0)])
        all_params = []
        all_forms = []
        all_urls = []

        parsed_base = urlparse(target_url)
        base_domain = parsed_base.hostname

        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True, verify=False
            ) as client:
                while queue and len(visited) < self.MAX_PAGES:
                    url, depth = queue.popleft()
                    norm = self._normalize(url)
                    if norm in visited:
                        continue
                    visited.add(norm)

                    try:
                        resp = await client.get(url, timeout=5.0)
                    except Exception:
                        continue

                    body = resp.text
                    all_urls.append(url)

                    # Extract params from this page
                    page_params = extract_params(url, body)
                    all_params.extend(page_params)

                    # Extract forms
                    forms = self._extract_forms(url, body)
                    all_forms.extend(forms)
                    # Also extract params from form actions
                    for form in forms:
                        for inp in form.get("inputs", []):
                            sep = "&" if "?" in form["action"] else "?"
                            form_url = f"{form['action']}{sep}{inp}=test"
                            all_params.append({"name": inp, "url": form_url})

                    # Discover new links if within depth
                    if depth < self.MAX_DEPTH:
                        links = self._extract_links(url, body, base_domain)
                        for link in links:
                            if self._normalize(link) not in visited:
                                queue.append((link, depth + 1))

                    if self.DELAY:
                        await asyncio.sleep(self.DELAY)

        except Exception as e:
            findings.append(self._make_finding(
                title="Crawler Error", severity=Severity.INFO,
                description=str(e), evidence=str(e),
            ))

        # Deduplicate params
        seen = set()
        unique_params = []
        for p in all_params:
            key = (p.get("url", "").split("?")[0], p["name"])
            if key not in seen:
                seen.add(key)
                unique_params.append(p)

        self.crawl_result = CrawlResult(
            urls=list(set(all_urls)),
            params=unique_params,
            forms=all_forms,
            pages_crawled=len(visited),
        )

        findings.append(self._make_finding(
            title=f"Discovered {len(all_urls)} Pages, {len(unique_params)} Parameters",
            severity=Severity.INFO,
            description=(
                f"Crawled {len(visited)} pages (depth {self.MAX_DEPTH}). "
                f"Found {len(unique_params)} injectable parameters across "
                f"{len(all_urls)} URLs and {len(all_forms)} forms."
            ),
            evidence=(
                f"Pages crawled: {len(visited)}\n"
                f"Unique URLs: {len(all_urls)}\n"
                f"Injectable params: {len(unique_params)}\n"
                f"Forms found: {len(all_forms)}\n"
                f"Sample URLs:\n" + "\n".join(all_urls[:10])
            ),
        ))

        return findings

    def _normalize(self, url: str) -> str:
        """Normalize URL for dedup (remove fragment, trailing slash)."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}?{parsed.query}"

    def _extract_links(self, base_url: str, body: str, domain: str) -> list[str]:
        """Extract same-domain links from HTML."""
        links = []
        # <a href="...">
        hrefs = re.findall(r'<a[^>]+href=["\']([^"\'#]+)', body, re.I)
        # Also check <form action="...">
        actions = re.findall(r'<form[^>]+action=["\']([^"\'#]+)', body, re.I)

        for href in hrefs + actions:
            href = href.strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            # Same domain only
            if parsed.hostname and parsed.hostname == domain:
                # Skip non-HTML resources
                ext = parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
                if ext in ("css", "js", "png", "jpg", "jpeg", "gif", "svg",
                           "ico", "woff", "woff2", "ttf", "eot", "mp4", "pdf"):
                    continue
                links.append(full)

        return links

    def _extract_forms(self, page_url: str, body: str) -> list[dict]:
        """Extract form details from HTML."""
        forms = []
        form_blocks = re.findall(
            r'<form([^>]*)>(.*?)</form>', body, re.I | re.DOTALL
        )
        for attrs, content in form_blocks:
            action_match = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            method_match = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
            action = urljoin(page_url, action_match.group(1)) if action_match else page_url
            method = (method_match.group(1).upper() if method_match else "GET")
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', content, re.I)
            # Also textarea and select
            inputs += re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', content, re.I)
            inputs += re.findall(r'<select[^>]+name=["\']([^"\']+)["\']', content, re.I)
            if inputs:
                forms.append({
                    "action": action,
                    "method": method,
                    "inputs": list(set(inputs)),
                })
        return forms
