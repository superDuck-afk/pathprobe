"""Central result collector — deduplication, scoring, and storage.

All findings flow through this single collector.  The scan engine
never appends to a raw list; it always goes through ``add()``, which
handles canonical deduplication and confidence scoring.
"""

from __future__ import annotations

import urllib.parse
from typing import Dict, List, Optional, Set

from pathprobe.core.types import Finding, PayloadMeta, Response, SignatureMatch, AnalysisResult
from pathprobe.core import config
from pathprobe.modules.response_analyzer import score_finding
from pathprobe.modules.poc_generator import PoCGenerator


class ResultCollector:
    """Thread-safe (well, asyncio-safe) central findings store."""

    def __init__(self):
        self._findings: List[Finding] = []
        self._seen_canonical: Set[str] = set()
        self._hits_per_param: Dict[str, int] = {}
        self._poc = PoCGenerator()
        self.total_requests = 0

    # ────────────────────────────────────────────────────────────────

    def _canonical_key(self, param: str, payload: str) -> str:
        """Produce a canonical form so encoded variants don't create
        duplicate findings."""
        decoded = urllib.parse.unquote(urllib.parse.unquote(payload))
        decoded = decoded.replace("\\", "/").replace("//", "/")
        return f"{param}||{decoded}"

    # ────────────────────────────────────────────────────────────────

    def add(
        self,
        param: str,
        payload: str,
        payload_meta: PayloadMeta,
        url: str,
        response: Response,
        result: AnalysisResult,
        post_mode: str = "GET",
        waf_technique: str = "none",
        verified: bool = False,
        consistent: bool = False,
        verification_count: int = 0,
    ) -> Optional[Finding]:
        """Add a finding.  Returns the ``Finding`` if accepted, else ``None``.

        Rejected if the canonical form was already seen (dedup).
        """
        key = self._canonical_key(param, payload)
        if key in self._seen_canonical:
            return None
        self._seen_canonical.add(key)

        # Update per-param hit counter
        self._hits_per_param[param] = self._hits_per_param.get(param, 0) + 1

        # Compute confidence score
        hit_count = self._hits_per_param[param]
        conf_score = score_finding(
            result,
            hit_count=hit_count,
            total_payloads=max(self.total_requests, 1),
            verified=verified,
        )

        finding = Finding(
            param=param,
            payload=payload,
            payload_meta=payload_meta,
            url=url,
            status=response.status,
            response_length=response.length,
            elapsed=response.elapsed,
            confidence=result.confidence,
            confidence_score=conf_score,
            signatures=list(result.matches),
            size_anomaly=result.size_anomaly,
            similarity_score=result.similarity_score,
            error_detected=result.error_detected,
            error_signatures_hit=list(result.error_signatures_hit),
            content_type_changed=result.content_type_changed,
            evidence_snippet=response.body[:config.EVIDENCE_MAX_BYTES],
            post_mode=post_mode,
            waf_technique=waf_technique,
            verified=verified,
            verification_count=verification_count,
            consistent=consistent,
            disclosed_paths=list(result.disclosed_paths),
        )

        # Attach PoC
        finding.curl_poc = self._poc.curl(finding)
        finding.python_poc = self._poc.python_script(finding)

        self._findings.append(finding)
        return finding

    # ────────────────────────────────────────────────────────────────

    def should_skip_param(self, param: str) -> bool:
        """Return True if we've already found enough HIGH-confidence
        hits on this param and should stop fuzzing it."""
        count = self._hits_per_param.get(param, 0)
        return count >= config.MAX_HIGH_FINDINGS_PER_PARAM

    @property
    def findings(self) -> List[Finding]:
        """All findings, sorted by confidence score descending."""
        return sorted(self._findings, key=lambda f: -f.confidence_score)

    @property
    def count(self) -> int:
        return len(self._findings)

    def hits_for_param(self, param: str) -> int:
        return self._hits_per_param.get(param, 0)

    def summary(self) -> Dict:
        """Build a summary dict for reporting."""
        sev_counts: Dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
        }
        for f in self._findings:
            for s in f.signatures:
                sev_counts[s.severity] = sev_counts.get(s.severity, 0) + 1
            if not f.signatures and (f.size_anomaly or f.error_detected):
                sev_counts["LOW"] += 1

        return {
            "severity_counts":     sev_counts,
            "affected_params":     list({f.param for f in self._findings}),
            "payload_categories":  list({f.payload_meta.category
                                         for f in self._findings}),
            "post_modes_hit":      list({f.post_mode for f in self._findings}),
            "waf_techniques_hit":  list({f.waf_technique
                                         for f in self._findings
                                         if f.waf_technique != "none"}),
            "verified_count":      sum(1 for f in self._findings if f.verified),
            "total_findings":      len(self._findings),
        }
