"""BFS crawler — discovers same-domain URLs for parameter extraction.

Runs synchronously (before the async scan loop starts) using urllib.
Extracts links from HTML, inline JS strings, and form actions.
"""

from __future__ import annotations

import re
import ssl
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Optional, Set

from pathprobe.core.config import (
    STATIC_EXTENSIONS, USER_AGENTS, C, G, DIM, RST,
)


class _LinkParser(HTMLParser):
    """Fast HTML parser that extracts links, form actions, and input names."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.links: Set[str] = set()
        self.forms: list = []       # [(action_url, method, [input_names])]
        self._cur_form = None
        self._cur_method = "POST"
        self._cur_inputs: list = []

    def _abs(self, url: str) -> str:
        return urllib.parse.urljoin(self.base, url)

    def handle_starttag(self, tag: str, attrs: list):
        d = dict(attrs)
        if tag == "a" and "href" in d:
            self.links.add(self._abs(d["href"]))
        elif tag == "link" and "href" in d:
            self.links.add(self._abs(d["href"]))
        elif tag == "script" and "src" in d:
            self.links.add(self._abs(d["src"]))
        elif tag == "img" and "src" in d:
            self.links.add(self._abs(d["src"]))
        elif tag == "iframe" and "src" in d:
            self.links.add(self._abs(d["src"]))
        elif tag == "form":
            self._cur_form = self._abs(d.get("action", ""))
            self._cur_method = d.get("method", "POST").upper()
            self._cur_inputs = []
        elif tag in ("input", "select", "textarea") and "name" in d:
            self._cur_inputs.append(d["name"])

    def handle_endtag(self, tag: str):
        if tag == "form" and self._cur_form is not None:
            self.forms.append((
                self._cur_form, self._cur_method, list(self._cur_inputs),
            ))
            self._cur_form = None
            self._cur_inputs = []


def _is_static(url: str) -> bool:
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def _same_domain(base: str, url: str) -> bool:
    return (urllib.parse.urlparse(base).netloc ==
            urllib.parse.urlparse(url).netloc)


def _strip_fragment(url: str) -> str:
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(p._replace(fragment=""))


def _fetch(url: str, timeout: int, verify_ssl: bool) -> Optional[dict]:
    """Simple sync GET for crawling."""
    headers = {"User-Agent": USER_AGENTS[0]}
    req = urllib.request.Request(url, headers=headers, method="GET")
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        start = time.time()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": body,
                "url": url,
            }
    except Exception:
        return None


def crawl(
    base_url: str,
    max_depth: int = 2,
    max_urls: int = 1000,
    timeout: int = 10,
    verify_ssl: bool = True,
    verbose: bool = False,
) -> Set[str]:
    """BFS crawl from *base_url*.  Returns discovered same-domain URLs."""
    visited: Set[str] = set()
    queue = [(_strip_fragment(base_url), 0)]
    visited.add(_strip_fragment(base_url))

    print(f"\n{C}[~] Crawling {base_url}  "
          f"(depth={max_depth}, max={max_urls})...{RST}")

    while queue and len(visited) < max_urls:
        url, depth = queue.pop(0)
        if depth > max_depth or _is_static(url):
            continue

        data = _fetch(url, timeout, verify_ssl)
        if not data or data["status"] >= 400:
            continue

        body = data.get("body", "")
        ct = data.get("headers", {}).get("Content-Type", "")

        # HTML parsing
        if "html" in ct.lower() or body.strip().startswith("<"):
            try:
                parser = _LinkParser(url)
                parser.feed(body)
                for link in parser.links:
                    link = _strip_fragment(link)
                    if link not in visited and _same_domain(base_url, link):
                        visited.add(link)
                        queue.append((link, depth + 1))
            except Exception:
                pass

        # Inline JS URL extraction
        for m in re.findall(
            r'["\'](/[a-zA-Z0-9_./-]+(?:\?[^"\' ]*)?)["\']', body,
        ):
            abs_m = urllib.parse.urljoin(url, m)
            abs_m = _strip_fragment(abs_m)
            if abs_m not in visited and _same_domain(base_url, abs_m):
                visited.add(abs_m)
                queue.append((abs_m, depth + 1))

        if verbose and len(visited) % 50 == 0:
            print(f"  {DIM}[crawl] {len(visited)} URLs...{RST}")

    print(f"{G}[+] Crawl complete:{RST} {len(visited)} URLs discovered")
    return visited
