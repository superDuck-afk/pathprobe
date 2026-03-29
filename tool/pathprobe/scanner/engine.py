"""Scan engine — two-phase adaptive fuzzing orchestrator.

This module is the async boundary: it owns the event loop and calls
synchronous modules (payload engine, response analyzer) from within
the async scan coroutines.

Pipeline:
  baseline → fingerprint → discovery → [adaptive expansion] → exploitation → verify → collect
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple

from pathprobe.core.types import (
    Finding, PayloadMeta, Response, ScanTarget, TargetInfo,
)
from pathprobe.core import config
from pathprobe.core.transport import AsyncTransport
from pathprobe.modules.payload_engine import PayloadEngine
from pathprobe.modules.waf_bypass import (
    apply_waf_transforms, apply_chained_waf_transforms, spoof_ip_headers,
)
from pathprobe.modules.response_analyzer import analyse as analyse_response
from pathprobe.modules.fingerprinter import TargetFingerprinter
from pathprobe.modules.verifier import verify_finding_async
from pathprobe.scanner.result_collector import ResultCollector


# ─────────────────────────────────────────────
#  POST body builders
# ─────────────────────────────────────────────

def _build_form(param: str, payload: str, **kw) -> Tuple[bytes, dict]:
    body = urllib.parse.urlencode({param: payload}).encode()
    return body, {"Content-Type": "application/x-www-form-urlencoded"}


def _build_json(param: str, payload: str, template: str = None, **kw) -> Tuple[bytes, dict]:
    try:
        data = json.loads(template) if template else {}
    except Exception:
        data = {}
    keys = param.split(".")
    node = data
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = payload
    return json.dumps(data).encode(), {"Content-Type": "application/json"}


def _build_xml(param: str, payload: str, **kw) -> Tuple[bytes, dict]:
    xml = (f'<?xml version="1.0" encoding="UTF-8"?>\n'
           f'<request>\n  <{param}>{payload}</{param}>\n'
           f'  <action>view</action>\n</request>')
    return xml.encode(), {"Content-Type": "application/xml"}


def _build_multipart(
    param: str,
    payload: str,
    filename_inject: bool = False,
    **kw,
) -> Tuple[bytes, dict]:
    boundary = "----PathProbe" + hashlib.md5(payload.encode()).hexdigest()[:12]
    if filename_inject:
        part = (f'--{boundary}\r\nContent-Disposition: form-data; '
                f'name="{param}"; filename="{payload}"\r\n'
                f'Content-Type: application/octet-stream\r\n\r\n'
                f'PATHPROBE_TEST\r\n')
    else:
        part = (f'--{boundary}\r\nContent-Disposition: form-data; '
                f'name="{param}"\r\n\r\n{payload}\r\n')
    body = (part + f'--{boundary}--\r\n').encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


POST_BUILDERS = {
    "form":      _build_form,
    "json":      _build_json,
    "xml":       _build_xml,
    "multipart": _build_multipart,
}


# ─────────────────────────────────────────────
#  Scan engine
# ─────────────────────────────────────────────

class ScanEngine:
    """Two-phase adaptive fuzzing engine."""

    def __init__(
        self,
        targets: List[ScanTarget],
        transport: AsyncTransport,
        collector: ResultCollector,
        *,
        waf_techniques: Optional[List[str]] = None,
        post_modes: Optional[List[str]] = None,
        json_template: Optional[str] = None,
        filename_inject: bool = False,
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
        aggressive: bool = False,
        verify: bool = True,
        verbose: bool = False,
        ip_spoof: bool = False,
    ):
        self.targets = targets
        self.transport = transport
        self.collector = collector
        self.engine = PayloadEngine()
        self.fingerprinter = TargetFingerprinter()

        self.waf_techniques = waf_techniques or []
        self.post_modes = post_modes or []
        self.json_template = json_template
        self.filename_inject = filename_inject
        self.extra_headers = extra_headers or {}
        self.cookies = cookies
        self.aggressive = aggressive
        self.do_verify = verify
        self.verbose = verbose

        if ip_spoof:
            self.extra_headers = spoof_ip_headers(self.extra_headers)

        self._fingerprint: Optional[TargetInfo] = None
        self._os_hint: Optional[str] = None

    # ────────────────────────────────────────────────────────────────
    #  Main entry point
    # ────────────────────────────────────────────────────────────────

    async def run(self) -> List[Finding]:
        """Execute the full scan pipeline.  Returns sorted findings."""
        # 1. Baseline + fingerprint (first target URL)
        primary_url = self.targets[0].url if self.targets else None
        if primary_url:
            baseline = await self.transport.get_baseline(
                primary_url,
                extra_headers=self.extra_headers,
                cookies=self.cookies,
            )
            if baseline:
                self._fingerprint = self.fingerprinter.fingerprint(baseline)
                self._os_hint = self.fingerprinter.select_os_hint(
                    self._fingerprint
                )
                self._print_fingerprint()

        # 2. Phase 1: Discovery — light fuzzing
        print(f"\n{config.C}[~] Phase 1: Discovery scan...{config.RST}")
        discovery_hits = await self._run_phase("discovery")

        # 3. Phase 2: Exploitation — deep fuzzing on promising params
        promising_params = self._promising_params(discovery_hits)
        if promising_params:
            print(f"\n{config.C}[~] Phase 2: Exploitation on "
                  f"{len(promising_params)} promising param(s)...{config.RST}")
            await self._run_phase("exploitation", filter_params=promising_params)
        else:
            print(f"\n{config.DIM}[~] Phase 2: Skipped (no discovery hits){config.RST}")

        return self.collector.findings

    # ────────────────────────────────────────────────────────────────
    #  Phase execution
    # ────────────────────────────────────────────────────────────────

    async def _run_phase(
        self,
        phase: str,
        filter_params: Optional[set] = None,
    ) -> List[Finding]:
        """Run one scan phase across all targets."""
        phase_findings: List[Finding] = []
        tasks = []

        for target in self.targets:
            if target.priority == "SKIP":
                continue
            if phase == "discovery" and target.priority == "LOW":
                continue
            if filter_params and target.param not in filter_params:
                continue

            baseline = await self.transport.get_baseline(
                target.url,
                extra_headers=self.extra_headers,
                cookies=self.cookies,
            )
            if not baseline:
                continue

            # Generate payloads for this phase
            payloads = list(self.engine.generate(
                os_hint=self._os_hint, phase=phase,
                aggressive=self.aggressive,
            ))

            # Add fingerprint-specific extras
            if self._fingerprint and self._fingerprint.extra_payloads:
                for payload_str, meta_dict in self._fingerprint.extra_payloads:
                    payloads.append((payload_str, PayloadMeta(
                        technique=meta_dict.get("technique", "fingerprint"),
                        phase=phase, category="fingerprint_specific",
                    )))

            # Schedule tasks
            tasks.append(self._fuzz_param(
                target, baseline, payloads, phase, phase_findings,
            ))

        if tasks:
            await asyncio.gather(*tasks)

        return phase_findings

    async def _fuzz_param(
        self,
        target: ScanTarget,
        baseline: Response,
        payloads: list,
        phase: str,
        phase_findings: list,
    ) -> None:
        """Fuzz one parameter with all payloads + WAF transforms."""
        param = target.param
        url = target.url

        for payload_str, meta in payloads:
            if self.collector.should_skip_param(param):
                break

            self.collector.total_requests += 1

            # ── GET ──────────────────────────────────────────────
            resp = await self.transport.get(
                url, param=param, payload=payload_str,
                extra_headers=self.extra_headers,
                cookies=self.cookies,
            )
            finding = await self._process_response(
                resp, baseline, param, payload_str, meta, url,
            )
            if finding:
                phase_findings.append(finding)
                # Adaptive: expand on hit during discovery
                if phase == "discovery":
                    await self._adaptive_expand(
                        target, baseline, meta, phase_findings,
                    )

            # ── POST modes ──────────────────────────────────────
            for pm in self.post_modes:
                if self.collector.should_skip_param(param):
                    break
                builder = POST_BUILDERS.get(pm)
                if not builder:
                    continue
                try:
                    kw = {}
                    if pm == "multipart":
                        kw["filename_inject"] = self.filename_inject
                    if pm == "json":
                        kw["template"] = self.json_template
                    body, ph = builder(param, payload_str, **kw)
                except Exception:
                    continue

                h = dict(self.extra_headers)
                h.update(ph)
                self.collector.total_requests += 1

                resp = await self.transport.post(
                    url, data=body, extra_headers=h, cookies=self.cookies,
                )
                finding = await self._process_response(
                    resp, baseline, param, payload_str, meta, url,
                    post_mode=pm,
                )
                if finding:
                    phase_findings.append(finding)

            # ── WAF transforms ──────────────────────────────────
            if self.waf_techniques:
                variants = apply_chained_waf_transforms(
                    payload_str, self.waf_techniques, max_chain_depth=2,
                )
                for tech_name, mutated in variants:
                    if self.collector.should_skip_param(param):
                        break
                    self.collector.total_requests += 1

                    resp = await self.transport.get(
                        url, param=param, payload=mutated,
                        extra_headers=self.extra_headers,
                        cookies=self.cookies,
                    )
                    waf_meta = PayloadMeta(
                        encoding=meta.encoding, depth=meta.depth,
                        target_file=meta.target_file,
                        technique=meta.technique, phase=phase,
                        separator=meta.separator,
                        category=meta.category,
                        waf_transform=tech_name,
                    )
                    finding = await self._process_response(
                        resp, baseline, param, mutated, waf_meta, url,
                        waf_technique=tech_name,
                    )
                    if finding:
                        phase_findings.append(finding)

    # ────────────────────────────────────────────────────────────────
    #  Response processing
    # ────────────────────────────────────────────────────────────────

    async def _process_response(
        self,
        resp: Optional[Response],
        baseline: Response,
        param: str,
        payload: str,
        meta: PayloadMeta,
        url: str,
        post_mode: str = "GET",
        waf_technique: str = "none",
    ) -> Optional[Finding]:
        """Analyse a response and optionally verify."""
        if resp is None:
            if self.verbose:
                print(f"  {config.DIM}[{self.collector.total_requests:04d}] "
                      f"TIMEOUT  param={param}  {payload[:50]}{config.RST}")
            return None

        result = analyse_response(resp, baseline, meta)

        if not result.vulnerable:
            if self.verbose:
                print(f"  {config.DIM}[{self.collector.total_requests:04d}] "
                      f"{resp.status}  param={param}  {payload[:50]}{config.RST}")
            return None

        # Verify (re-send to confirm)
        verified = False
        consistent = False
        v_count = 0
        if self.do_verify and result.confidence in ("HIGH", "MEDIUM"):
            verified, consistent, v_count = await verify_finding_async(
                self.transport, url, param, payload, "GET",
                baseline, meta,
                extra_headers=self.extra_headers,
                cookies=self.cookies,
            )

        finding = self.collector.add(
            param=param, payload=payload, payload_meta=meta,
            url=resp.url, response=resp, result=result,
            post_mode=post_mode, waf_technique=waf_technique,
            verified=verified, consistent=consistent,
            verification_count=v_count,
        )

        if finding:
            self._print_finding(finding)

        return finding

    # ────────────────────────────────────────────────────────────────
    #  Adaptive expansion
    # ────────────────────────────────────────────────────────────────

    async def _adaptive_expand(
        self,
        target: ScanTarget,
        baseline: Response,
        hit_meta: PayloadMeta,
        phase_findings: list,
    ) -> None:
        """When a discovery hit occurs, generate and test adaptive payloads."""
        param = target.param
        url = target.url

        adaptive_payloads = list(self.engine.expand_on_hit(
            hit_meta, os_hint=self._os_hint,
        ))

        if adaptive_payloads and self.verbose:
            print(f"  {config.C}[ADAPT] Expanding {len(adaptive_payloads)} "
                  f"payloads for {param}{config.RST}")

        for payload_str, meta in adaptive_payloads[:50]:  # Cap expansion
            if self.collector.should_skip_param(param):
                break
            self.collector.total_requests += 1

            resp = await self.transport.get(
                url, param=param, payload=payload_str,
                extra_headers=self.extra_headers,
                cookies=self.cookies,
            )
            finding = await self._process_response(
                resp, baseline, param, payload_str, meta, url,
            )
            if finding:
                phase_findings.append(finding)

    # ────────────────────────────────────────────────────────────────
    #  Helpers
    # ────────────────────────────────────────────────────────────────

    def _promising_params(self, discovery_findings: List[Finding]) -> set:
        """Return set of param names that had discovery-phase hits."""
        return {f.param for f in discovery_findings}

    def _print_fingerprint(self) -> None:
        if not self._fingerprint:
            return
        fp = self._fingerprint
        parts = []
        if fp.os:
            parts.append(f"OS={fp.os}")
        if fp.server:
            parts.append(f"Server={fp.server}")
        if fp.language:
            parts.append(f"Lang={fp.language}")
        if fp.framework:
            parts.append(f"Framework={fp.framework}")
        if parts:
            print(f"{config.G}[+] Fingerprint: {', '.join(parts)}{config.RST}")
            if self._os_hint:
                print(f"    {config.DIM}Payloads filtered for: "
                      f"{self._os_hint}{config.RST}")

    def _print_finding(self, f: Finding) -> None:
        sev = f.severity
        sc = (config.R if sev == "CRITICAL" else
              config.Y if sev == "HIGH" else config.M)
        pm_tag = f"{config.C}[{f.post_mode}]{config.RST} " if f.post_mode != "GET" else ""
        waf_tag = (f"{config.M}[WAF:{f.waf_technique}]{config.RST} "
                   if f.waf_technique != "none" else "")
        err_tag = f"{config.Y}[ERR]{config.RST} " if f.error_detected else ""
        ver_tag = (f"{config.G}[✓]{config.RST} " if f.verified
                   else f"{config.DIM}[?]{config.RST} ")
        sim_tag = (f"{config.DIM}[sim:{f.similarity_score:.2f}]{config.RST} "
                   if f.similarity_score < 1.0 else "")
        score_tag = f"{config.DIM}[{f.confidence_score}/100]{config.RST} "

        print(f"  {config.R}[VULN]{config.RST} {sc}{sev:<8}{config.RST}  "
              f"{score_tag}{ver_tag}{pm_tag}{waf_tag}{err_tag}{sim_tag}"
              f"param={config.BOLD}{f.param}{config.RST}  "
              f"{config.G}{f.payload[:52]}{config.RST}")
        for m in f.signatures:
            print(f"         {config.DIM}↳ {m.description} "
                  f"(OS: {m.os}){config.RST}")
        if f.error_detected and f.error_signatures_hit:
            print(f"         {config.Y}↳ Error-based: "
                  f"{', '.join(f.error_signatures_hit)}{config.RST}")
        if f.disclosed_paths:
            print(f"         {config.C}↳ Paths: "
                  f"{', '.join(f.disclosed_paths[:3])}{config.RST}")
