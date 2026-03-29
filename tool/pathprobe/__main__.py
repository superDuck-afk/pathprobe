"""PathProbe v3.0 — entry point.

Usage:
    python -m pathprobe <url> [options]
    python pathprobe/__main__.py <url> [options]
"""

from __future__ import annotations

import asyncio
import os
import platform
import sys
import time
from typing import Dict, List, Optional

from pathprobe.cli import build_parser
from pathprobe.core.types import ScanTarget
from pathprobe.core.transport import AsyncTransport
from pathprobe.modules.param_analyzer import analyse_params
from pathprobe.modules.payload_engine import PayloadEngine
from pathprobe.modules.zipslip import ZipSlipTester
from pathprobe.scanner.engine import ScanEngine, POST_BUILDERS
from pathprobe.scanner.result_collector import ResultCollector
from pathprobe.recon.crawler import crawl
from pathprobe.recon.param_extractor import extract_params
from pathprobe.reporting.console import (
    print_banner, print_legal_notice, print_scan_config,
    print_param_summary, print_baseline, print_scan_complete,
)
from pathprobe.reporting.reporter import generate_reports
from pathprobe.core import config


# ─────────────────────────────────────────────
#  ZipSlip standalone commands
# ─────────────────────────────────────────────

def _handle_zipslip(args) -> bool:
    """Handle --zipslip-generate and --zipslip-test.

    Returns True if a ZipSlip command was handled (skip normal scan).
    """
    tester = ZipSlipTester()

    if args.zipslip_generate:
        path = args.zipslip_generate
        if path.endswith(".tar.gz") or path.endswith(".tgz"):
            tester.save_tar(path)
            fmt = "TAR.GZ"
        else:
            if not path.endswith(".zip"):
                path += ".zip"
            tester.save_zip(path)
            fmt = "ZIP"
        print(f"{config.G}[+] Malicious {fmt} archive saved: {path}{config.RST}")
        print(f"    Entries:")
        entries = tester.list_archive_entries(
            "tar" if "tar" in path else "zip"
        )
        for e in entries:
            print(f"      {e}")
        return True

    return False


# ─────────────────────────────────────────────
#  Main async scan
# ─────────────────────────────────────────────

async def _async_scan(args) -> None:
    """Run the full async scan pipeline."""

    # ── Parse compound CLI args ──────────────────────────────────
    manual_params = [p.strip() for p in args.param.split(",")]

    post_modes: List[str] = []
    if args.post_mode:
        raw = [m.strip() for m in args.post_mode.split(",")]
        post_modes = (list(POST_BUILDERS.keys()) if "all" in raw
                      else [m for m in raw if m in POST_BUILDERS])

    waf_techniques: List[str] = []
    if args.waf_bypass:
        raw = [t.strip() for t in args.waf_bypass.split(",")]
        waf_techniques = raw  # "all" handled downstream

    extra_headers: Dict[str, str] = {}
    if args.headers:
        for h in args.headers.split(";"):
            if ":" in h:
                k, v = h.split(":", 1)
                extra_headers[k.strip()] = v.strip()

    report_formats = [f.strip() for f in args.report.split(",")]

    # ── Recon (crawl + extract + score) ──────────────────────────
    scan_targets: List[ScanTarget] = []

    if args.crawl:
        urls = crawl(
            args.url, max_depth=args.crawl, max_urls=args.max_urls,
            timeout=args.timeout, verify_ssl=not args.no_ssl_verify,
            verbose=args.verbose,
        )
        crawled_targets = extract_params(
            urls, timeout=args.timeout,
            verify_ssl=not args.no_ssl_verify,
        )
        if crawled_targets:
            print(f"\n{config.C}[~] Scoring discovered parameters...{config.RST}")
            analyse_params(
                crawled_targets, timeout=args.timeout,
                verify_ssl=not args.no_ssl_verify,
                verbose=args.verbose,
            )
            scan_targets.extend(crawled_targets)

    # Always add user-specified params as HIGH priority
    for param in manual_params:
        scan_targets.insert(0, ScanTarget(
            url=args.url, param=param, method="GET",
            priority="HIGH", score=99,
        ))

    if not scan_targets:
        print(f"{config.Y}[!] No targets to scan.{config.RST}")
        return

    # Print param summary
    print_param_summary(scan_targets)

    # ── Print config ─────────────────────────────────────────────
    print_scan_config(
        url=args.url,
        params=[t.param for t in scan_targets[:10]],
        total_payloads=0,  # computed dynamically
        method=args.method,
        threads=min(max(1, args.threads), 100),
        rate=args.rate,
        retries=args.retries,
        post_modes=post_modes,
        waf_bypass=args.waf_bypass,
        ip_spoof=args.waf_ip_spoof,
        wordlist=args.wordlist,
        aggressive=args.aggressive,
        verify=not args.no_verify,
    )

    # ── Run scan ─────────────────────────────────────────────────
    collector = ResultCollector()
    concurrency = min(max(1, args.threads), 100)

    async with AsyncTransport(
        concurrency=concurrency,
        rate_limit=args.rate,
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        retries=args.retries,
    ) as transport:

        # Baseline
        print(f"\n{config.C}[~] Getting baseline response...{config.RST}")
        baseline = await transport.get_baseline(
            args.url, extra_headers=extra_headers, cookies=args.cookies,
        )
        if baseline:
            print_baseline(baseline.status, baseline.length, baseline.elapsed)
        else:
            print(f"{config.Y}[!] Baseline failed — proceeding{config.RST}")

        # Engine
        engine = ScanEngine(
            targets=scan_targets,
            transport=transport,
            collector=collector,
            waf_techniques=waf_techniques,
            post_modes=post_modes,
            json_template=args.json_template,
            filename_inject=args.filename_inject,
            extra_headers=extra_headers,
            cookies=args.cookies,
            aggressive=args.aggressive,
            verify=not args.no_verify,
            verbose=args.verbose,
            ip_spoof=args.waf_ip_spoof,
        )

        # Add wordlist payloads as extra targets
        # (handled by extending the payload engine in the scan)

        start_time = time.time()
        print(f"\n{config.C}[~] Starting adaptive scan...{config.RST}\n")

        findings = await engine.run()

        elapsed = round(time.time() - start_time, 2)

    # ── Results ──────────────────────────────────────────────────
    print_scan_complete(collector, elapsed)

    if collector.count:
        # PoC terminal blocks for top findings
        from pathprobe.modules.poc_generator import PoCGenerator
        poc = PoCGenerator()
        print(f"\n{config.BOLD}[*] Detailed PoCs:{config.RST}")
        for i, f in enumerate(collector.findings[:5], 1):
            print(poc.terminal_block(f, i))

        # File reports
        print(f"\n{config.BOLD}[*] Generating reports ({args.report})...{config.RST}")
        generate_reports(collector, args.url, report_formats)

    print()


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────

def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()
    print_legal_notice()

    # ZipSlip standalone commands
    if _handle_zipslip(args):
        return

    try:
        # aiohttp requires SelectorEventLoop on Windows; Linux/macOS work
        # out of the box.  Set the policy before asyncio.run() so the
        # correct loop type is created.
        if platform.system() == "Windows":
            asyncio.set_event_loop_policy(
                asyncio.WindowsSelectorEventLoopPolicy()
            )
        asyncio.run(_async_scan(args))
    except KeyboardInterrupt:
        print(f"\n\n{config.Y}[!] Interrupted.{config.RST}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
