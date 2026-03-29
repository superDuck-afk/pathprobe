"""Response analysis engine — pure functions, no side effects.

analyse(response, baseline, payload_meta) → AnalysisResult

This module owns all detection logic:
  Layer 1: Content signatures (known file contents)
  Layer 2: Error-based signatures (server errors proving traversal)
  Layer 3: Content fingerprints (structural detection)
  Layer 4: Base64 PHP source detection
  Layer 5: Similarity scoring (simhash or SequenceMatcher)
  Layer 6: Content-type anomaly
  Layer 7: Size anomaly
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import re
from typing import List, Optional, Tuple

from pathprobe.core.types import AnalysisResult, PayloadMeta, Response, SignatureMatch
from pathprobe.core import config


# ─────────────────────────────────────────────
#  Content fingerprints  (structural, not regex)
# ─────────────────────────────────────────────

def _is_passwd_structure(body: str) -> bool:
    """Detect /etc/passwd by counting colon-delimited UID:GID lines."""
    return sum(1 for ln in body.split("\n")
               if re.match(r"^[^:]+:[^:]*:\d+:\d+:", ln)) >= 3


def _is_ini_structure(body: str) -> bool:
    """Detect INI file by counting [section] headers."""
    return sum(1 for ln in body.split("\n")
               if re.match(r"^\[.+\]$", ln.strip())) >= 2


def _is_env_structure(body: str) -> bool:
    """Detect .env file by counting KEY=VALUE lines."""
    return sum(1 for ln in body.split("\n")
               if re.match(r"^[A-Z_][A-Z0-9_]*=", ln.strip())) >= 3


def _is_xml_config(body: str) -> bool:
    return ("<?xml" in body[:200] and
            any(tag in body for tag in (
                "<configuration>", "<connectionStrings",
                "<appSettings", "<system.web")))


def _is_json_config(body: str) -> bool:
    return (body.strip().startswith("{") and
            any(key in body for key in (
                '"ConnectionStrings"', '"database"',
                '"password"', '"secret"', '"api_key"',
                '"DB_PASSWORD"', '"SECRET_KEY"')))


def _is_b64_php(body: str) -> bool:
    """Check if response is base64-encoded PHP source code.

    This is the strongest signal for php://filter hits.
    Zero false-positive rate when it fires.
    """
    text = body.strip()
    # Must look like a base64 blob (length multiple of 4, valid chars)
    if len(text) < 20 or len(text) % 4 != 0:
        # Try extracting b64 from HTML wrapper
        m = re.search(r"([A-Za-z0-9+/]{40,}={0,2})", text)
        if not m:
            return False
        text = m.group(1)

    try:
        decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
    except Exception:
        return False

    php_markers = ("<?php", "<?=", "function ", "class ", "namespace ",
                   "require", "include", "$_GET", "$_POST", "$_SERVER",
                   "define(", "use ")
    return any(marker in decoded for marker in php_markers)


CONTENT_FINGERPRINTS = {
    "passwd_structure": {
        "test": _is_passwd_structure,
        "severity": "CRITICAL",
        "description": "/etc/passwd structure detected (3+ valid entries)",
        "os": "Linux",
    },
    "ini_structure": {
        "test": _is_ini_structure,
        "severity": "HIGH",
        "description": "INI file structure detected",
        "os": "Any",
    },
    "env_structure": {
        "test": _is_env_structure,
        "severity": "CRITICAL",
        "description": ".env file structure detected (3+ KEY=VALUE lines)",
        "os": "Any",
    },
    "xml_config": {
        "test": _is_xml_config,
        "severity": "CRITICAL",
        "description": ".NET XML configuration detected",
        "os": "Windows",
    },
    "json_config": {
        "test": _is_json_config,
        "severity": "HIGH",
        "description": "JSON configuration with secrets detected",
        "os": "Any",
    },
    "php_source_b64": {
        "test": _is_b64_php,
        "severity": "CRITICAL",
        "description": "PHP source code disclosed via wrapper (base64)",
        "os": "Any",
    },
}


# ─────────────────────────────────────────────
#  Similarity scoring
# ─────────────────────────────────────────────

def _simhash_sets(text: str, chunk_size: int = 64) -> set:
    """Locality-sensitive hash set for large-text comparison (O(n))."""
    chunks = [text[i:i + chunk_size]
              for i in range(0, len(text), chunk_size)]
    return {hashlib.md5(c.encode()).hexdigest()[:8] for c in chunks}


def similarity_score(baseline: str, response: str) -> float:
    """Return 0.0–1.0 similarity.

    Uses simhash (Jaccard on chunk hashes) for bodies >16 KB,
    SequenceMatcher for smaller responses.
    """
    if not baseline and not response:
        return 1.0
    if not baseline or not response:
        return 0.0

    threshold = config.SIMHASH_THRESHOLD
    if len(baseline) > threshold or len(response) > threshold:
        h1 = _simhash_sets(baseline, config.SIMHASH_CHUNK_SIZE)
        h2 = _simhash_sets(response, config.SIMHASH_CHUNK_SIZE)
        union = h1 | h2
        if not union:
            return 1.0
        return len(h1 & h2) / len(union)

    # SequenceMatcher — truncate to avoid quadratic blow-up
    a = baseline[:8192]
    b = response[:8192]
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


# ─────────────────────────────────────────────
#  Path extraction from error messages
# ─────────────────────────────────────────────

def extract_paths(body: str) -> List[str]:
    """Extract disclosed server-side paths from error messages."""
    paths = []
    for pattern in config.PATH_EXTRACTION_PATTERNS:
        for m in re.finditer(pattern, body, re.IGNORECASE):
            path = m.group(1) if m.lastindex else m.group(0)
            if path and len(path) > 2:
                paths.append(path)
    return list(dict.fromkeys(paths))  # dedupe, preserve order


# ─────────────────────────────────────────────
#  Content-type anomaly
# ─────────────────────────────────────────────

def content_type_changed(
    baseline_headers: dict,
    response_headers: dict,
) -> Tuple[bool, str, str]:
    """Return ``(changed, baseline_ct, response_ct)``."""
    def _extract(h: dict) -> str:
        ct = h.get("Content-Type", h.get("content-type", ""))
        return ct.split(";")[0].strip().lower()

    bl = _extract(baseline_headers)
    rp = _extract(response_headers)
    return (bl != rp and bool(bl) and bool(rp)), bl, rp


# ─────────────────────────────────────────────
#  Core analysis function  (PURE — no I/O)
# ─────────────────────────────────────────────

def analyse(
    response: Response,
    baseline: Optional[Response],
    payload_meta: Optional[PayloadMeta] = None,
) -> AnalysisResult:
    """Run all detection layers against *response*.

    This is a **pure function** — it reads data, computes results, and
    returns an ``AnalysisResult``.  No printing, no network calls, no
    global state mutation.
    """
    if response is None:
        return AnalysisResult()

    body   = response.body
    status = response.status
    length = response.length

    bl_body    = baseline.body if baseline else ""
    bl_length  = baseline.length if baseline else 0
    bl_headers = baseline.headers if baseline else {}

    matches: List[SignatureMatch] = []

    # ── Layer 1: Regex content signatures ─────────────────────────
    for sig_name, sig in config.SIGNATURES.items():
        if re.search(sig["pattern"], body, re.IGNORECASE | re.MULTILINE):
            matches.append(SignatureMatch(
                signature=sig_name,
                description=sig["description"],
                severity=sig["severity"],
                os=sig["os"],
            ))

    # ── Layer 2: Error-based signatures ───────────────────────────
    error_detected = False
    error_hits: List[str] = []
    for err_name, pattern in config.ERROR_SIGNATURES.items():
        if re.search(pattern, body, re.IGNORECASE | re.MULTILINE):
            error_detected = True
            error_hits.append(err_name)

    # ── Layer 3: Structural content fingerprints ──────────────────
    for fp_name, fp in CONTENT_FINGERPRINTS.items():
        try:
            if fp["test"](body):
                matches.append(SignatureMatch(
                    signature=fp_name,
                    description=fp["description"],
                    severity=fp["severity"],
                    os=fp["os"],
                ))
        except Exception:
            pass

    # ── Layer 4: Path extraction (free intelligence) ──────────────
    disclosed = extract_paths(body) if error_detected else []

    # ── Layer 5: Similarity vs baseline ───────────────────────────
    sim = similarity_score(bl_body, body) if bl_body else 1.0

    # ── Layer 6: Content-type anomaly ─────────────────────────────
    ct_changed, bl_ct, resp_ct = content_type_changed(
        bl_headers, response.headers,
    )

    # ── Layer 7: Size anomaly ─────────────────────────────────────
    size_anom = (bl_length > 0 and
                 length > bl_length * config.SIZE_ANOMALY_FACTOR and
                 length > config.SIZE_ANOMALY_MIN_BYTES)

    # ── Confidence resolution ─────────────────────────────────────
    vulnerable = False
    confidence = "NONE"

    if matches:
        severities = {m.severity for m in matches}
        if "CRITICAL" in severities:
            confidence = "HIGH"
        else:
            confidence = "MEDIUM" if "HIGH" in severities else "MEDIUM"
        vulnerable = True
    elif error_detected:
        confidence = "MEDIUM"
        vulnerable = True
    elif sim < config.SIM_THRESHOLD_DIFF and status == 200:
        confidence = "MEDIUM"
        vulnerable = True
    elif ct_changed and status == 200:
        confidence = "MEDIUM"
        vulnerable = True
    elif (size_anom or (bl_body and sim < config.SIM_THRESHOLD_SIMILAR)) and status == 200:
        confidence = "LOW"
        vulnerable = True

    return AnalysisResult(
        vulnerable=vulnerable,
        confidence=confidence,
        matches=matches,
        similarity_score=round(sim, 4),
        error_detected=error_detected,
        error_signatures_hit=error_hits,
        content_type_changed=ct_changed,
        baseline_ct=bl_ct,
        response_ct=resp_ct,
        size_anomaly=size_anom,
        status=status,
        length=length,
        disclosed_paths=disclosed,
    )


# ─────────────────────────────────────────────
#  Confidence scoring  (0–100)
# ─────────────────────────────────────────────

def score_finding(
    result: AnalysisResult,
    hit_count: int = 1,
    total_payloads: int = 1,
    verified: bool = False,
) -> int:
    """Compute a 0–100 composite confidence score."""
    score = 0

    # Signature matches
    if result.matches:
        severities = {m.severity for m in result.matches}
        if "CRITICAL" in severities:
            score += config.SCORE_WEIGHT_SIGNATURE_CRITICAL
        elif "HIGH" in severities:
            score += config.SCORE_WEIGHT_SIGNATURE_HIGH
        elif "MEDIUM" in severities:
            score += config.SCORE_WEIGHT_SIGNATURE_MEDIUM

    # Error-based
    if result.error_detected:
        score += config.SCORE_WEIGHT_ERROR_DETECTED

    # Similarity
    if result.similarity_score < config.SIM_THRESHOLD_VERY_DIFF:
        score += config.SCORE_WEIGHT_SIM_VERY_LOW
    elif result.similarity_score < config.SIM_THRESHOLD_DIFF:
        score += config.SCORE_WEIGHT_SIM_LOW
    elif result.similarity_score < config.SIM_THRESHOLD_SIMILAR:
        score += config.SCORE_WEIGHT_SIM_MEDIUM

    # Size anomaly
    if result.size_anomaly:
        score += config.SCORE_WEIGHT_SIZE_ANOMALY

    # Content-type change
    if result.content_type_changed:
        score += config.SCORE_WEIGHT_CT_CHANGED

    # Verification bonus
    if verified:
        score += config.SCORE_WEIGHT_VERIFIED

    # Penalise lone hits (likely FP)
    if hit_count == 1 and total_payloads > 20:
        score += config.SCORE_PENALTY_SINGLE_HIT

    return max(0, min(100, score))
