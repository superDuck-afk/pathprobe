"""Parameter extraction from crawled URLs, forms, and JSON responses.

Produces ``ScanTarget`` objects ready for the scan engine.
"""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.parse
import urllib.request
from typing import List, Optional, Set

from pathprobe.core.types import ScanTarget
from pathprobe.core.config import (
    FILE_PARAM_HINTS, STATIC_EXTENSIONS, USER_AGENTS, C, G, DIM, RST,
)
from pathprobe.recon.crawler import _LinkParser, _is_static


def _fetch(url: str, timeout: int, verify_ssl: bool) -> Optional[dict]:
    """Simple sync GET."""
    headers = {"User-Agent": USER_AGENTS[0]}
    req = urllib.request.Request(url, headers=headers, method="GET")
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
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


def extract_params(
    urls: Set[str],
    timeout: int = 10,
    verify_ssl: bool = True,
) -> List[ScanTarget]:
    """Extract parameters from URLs, forms, and JSON responses.

    Returns a list of ``ScanTarget`` objects (one per (url, param) pair).
    """
    targets: List[ScanTarget] = []
    seen: Set[str] = set()  # (base_url, method, param) dedup key

    for url in urls:
        if _is_static(url):
            continue

        parsed = urllib.parse.urlparse(url)
        base_url = urllib.parse.urlunparse(
            parsed._replace(query="", fragment=""),
        )

        # 1. Query-string parameters
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for param, values in qs.items():
            key = (base_url, "GET", param)
            if key in seen:
                continue
            seen.add(key)
            targets.append(ScanTarget(
                url=url, param=param, method="GET",
                param_value=values[0] if values else "",
            ))

        # 2. REST-style path segments (/download/file/test.txt)
        segments = [s for s in parsed.path.split("/") if s]
        if len(segments) >= 2:
            for i in range(len(segments) - 1):
                seg = segments[i].lower()
                if seg in FILE_PARAM_HINTS:
                    p_name = segments[i]
                    key = (base_url, "REST", p_name)
                    if key not in seen:
                        seen.add(key)
                        # For REST params, the "value" is the next segment
                        val = segments[i + 1] if i + 1 < len(segments) else ""
                        targets.append(ScanTarget(
                            url=base_url, param=p_name, method="GET",
                            param_value=val,
                        ))

        # 3. Fetch page for form/JSON extraction
        data = _fetch(url, timeout, verify_ssl)
        if not data:
            continue
        body = data.get("body", "")
        ct = data.get("headers", {}).get("Content-Type", "")

        # Form inputs
        if "html" in ct.lower() or body.strip().startswith("<"):
            try:
                parser = _LinkParser(url)
                parser.feed(body)
                for form_url, method, input_names in parser.forms:
                    for inp in input_names:
                        key = (form_url, method, inp)
                        if key not in seen:
                            seen.add(key)
                            targets.append(ScanTarget(
                                url=form_url, param=inp, method=method,
                            ))
            except Exception:
                pass

        # JSON top-level keys
        if "json" in ct.lower() or body.strip().startswith("{"):
            try:
                jdata = json.loads(body)
                if isinstance(jdata, dict):
                    for jkey in list(jdata.keys())[:20]:
                        key = (base_url, "POST", jkey)
                        if key not in seen:
                            seen.add(key)
                            val = str(jdata[jkey]) if not isinstance(
                                jdata[jkey], (dict, list)) else ""
                            targets.append(ScanTarget(
                                url=base_url, param=jkey, method="POST",
                                param_value=val,
                                post_mode="json",
                            ))
            except Exception:
                pass

    print(f"{G}[+] Extracted {len(targets)} parameter targets "
          f"from {len(urls)} URLs{RST}")
    return targets
