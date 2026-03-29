"""Smart parameter targeting — value-based + behavioral scoring.

Replaces the v2 static name-hint approach with:
  A. Value-based detection (regex on current parameter value)
  B. Response-behavior probing (mutate → compare)
  C. Heuristic scoring with calibrated thresholds
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
import urllib.parse
import urllib.request
import ssl
from typing import Dict, List, Optional, Tuple

from pathprobe.core.types import ParamScore, Response, ScanTarget
from pathprobe.core import config


# ─────────────────────────────────────────────
#  Value-based detection
# ─────────────────────────────────────────────

def score_param_value(name: str, value: str) -> Tuple[int, List[str]]:
    """Score a parameter based on its current VALUE.

    Returns ``(score, [signals])`` where each signal is a string
    describing why the score was given.
    """
    score = 0
    signals: List[str] = []

    if not value:
        # Name-only hint (weak)
        if name.lower() in config.FILE_PARAM_HINTS:
            return 1, ["name_hint"]
        return 0, []

    for pattern_name, regex in config.VALUE_PATTERNS.items():
        if re.search(regex, value, re.IGNORECASE):
            score += 3
            signals.append(f"value:{pattern_name}")

    # Base64 decode and check for hidden paths
    try:
        decoded = base64.b64decode(value).decode("utf-8", errors="ignore")
        for pname, regex in config.VALUE_PATTERNS.items():
            if pname == "base64_path":
                continue  # Don't recurse
            if re.search(regex, decoded, re.IGNORECASE):
                score += 4
                signals.append(f"b64_value:{pname}")
    except Exception:
        pass

    # Name hint — weak boost (max +1)
    if name.lower() in config.FILE_PARAM_HINTS:
        score += 1
        signals.append("name_hint")

    return score, signals


# ─────────────────────────────────────────────
#  Sync HTTP helper  (used only during recon phase)
# ─────────────────────────────────────────────

def _sync_request(
    url: str,
    timeout: int = 10,
    verify_ssl: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> Optional[Response]:
    """Simple sync GET using urllib.  Used for recon probing (before
    the async scan loop starts)."""
    h = headers or {}
    h.setdefault("User-Agent", config.USER_AGENTS[0])
    req = urllib.request.Request(url, headers=h, method="GET")

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        start = time.time()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return Response(
                status=resp.status,
                headers=dict(resp.headers),
                body=body,
                length=len(body),
                elapsed=round(time.time() - start, 3),
                url=url,
            )
    except urllib.error.HTTPError as e:
        elapsed = round(time.time() - start, 3)
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return Response(
            status=e.code,
            headers=dict(e.headers) if e.headers else {},
            body=body, length=len(body), elapsed=elapsed, url=url,
        )
    except Exception:
        return None


# ─────────────────────────────────────────────
#  Behavioral probing
# ─────────────────────────────────────────────

_PROBES = [
    "test.txt",
    "../test",
    "/etc/passwd",
    "pathprobe_canary_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
]


def probe_param(
    url: str,
    param: str,
    baseline: Response,
    timeout: int = 10,
    verify_ssl: bool = True,
) -> Tuple[int, List[str]]:
    """Send safe probes for one (url, param) pair and score behaviour.

    Returns ``(score, [signals])``.
    """
    score = 0
    signals: List[str] = []
    bl_len = baseline.length
    bl_stat = baseline.status
    bl_body = baseline.body[:4096]
    bl_ct = baseline.headers.get("Content-Type",
                                  baseline.headers.get("content-type", ""))

    for probe in _PROBES:
        # Build URL with probe value
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [probe]
        probe_url = parsed._replace(
            query=urllib.parse.urlencode(qs, doseq=True)
        ).geturl()

        resp = _sync_request(probe_url, timeout=timeout,
                             verify_ssl=verify_ssl)
        if resp is None:
            continue

        # Size change (>20%)
        if bl_len > 0 and abs(resp.length - bl_len) / max(bl_len, 1) > 0.20:
            score += 2
            signals.append(f"size_change:{probe}")

        # Similarity
        from pathprobe.modules.response_analyzer import similarity_score
        sim = similarity_score(bl_body, resp.body[:4096])
        if sim < 0.70:
            score += 3
            signals.append(f"very_different:{probe}")
        elif sim < 0.90:
            score += 1
            signals.append(f"different:{probe}")

        # Error signatures
        for _, pat in config.ERROR_SIGNATURES.items():
            if re.search(pat, resp.body, re.IGNORECASE):
                score += 3
                signals.append(f"error_hit:{probe}")
                break

        # Status code change
        if resp.status != bl_stat:
            score += 2
            signals.append(f"status_change:{resp.status}")

        # Content-type change
        resp_ct = resp.headers.get("Content-Type",
                                    resp.headers.get("content-type", ""))
        if bl_ct and resp_ct and bl_ct.split(";")[0] != resp_ct.split(";")[0]:
            score += 2
            signals.append(f"ct_change:{resp_ct}")

        # Probe value reflected in response
        if probe in resp.body:
            score += 1
            signals.append(f"reflected:{probe}")

    return score, signals


# ─────────────────────────────────────────────
#  Full parameter analysis
# ─────────────────────────────────────────────

def analyse_params(
    targets: List[ScanTarget],
    timeout: int = 10,
    verify_ssl: bool = True,
    verbose: bool = False,
) -> List[ScanTarget]:
    """Score and prioritise all parameters across all targets.

    Modifies *targets* in-place, setting ``priority`` and ``score``.
    Returns the same list, sorted by score descending.
    """
    # Cache baselines per URL
    baseline_cache: Dict[str, Response] = {}

    for target in targets:
        url = target.url

        # Get cached baseline
        if url not in baseline_cache:
            bl = _sync_request(url, timeout=timeout, verify_ssl=verify_ssl)
            if bl is None:
                target.priority = "SKIP"
                target.score = 0
                continue
            baseline_cache[url] = bl
        baseline = baseline_cache[url]

        total_score = 0
        all_signals: List[str] = []

        # A. Value-based scoring
        vs, v_signals = score_param_value(target.param, target.param_value)
        total_score += vs
        all_signals.extend(v_signals)

        # B. Behavioral probing
        bs, b_signals = probe_param(
            url, target.param, baseline,
            timeout=timeout, verify_ssl=verify_ssl,
        )
        total_score += bs
        all_signals.extend(b_signals)

        # Assign priority
        if total_score >= config.PARAM_SCORE_HIGH:
            target.priority = "HIGH"
        elif total_score >= config.PARAM_SCORE_MEDIUM:
            target.priority = "MEDIUM"
        elif total_score > 0:
            target.priority = "LOW"
        else:
            target.priority = "SKIP"
        target.score = total_score

        if verbose:
            pc = (config.R if target.priority == "HIGH" else
                  config.Y if target.priority == "MEDIUM" else config.DIM)
            print(f"  {pc}{target.param:>20} → {target.priority} "
                  f"(score: {total_score}, signals: {all_signals}){config.RST}")

    # Sort: HIGH first, then by score descending
    prio_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "SKIP": 3}
    targets.sort(key=lambda t: (prio_order.get(t.priority, 9), -t.score))
    return targets
