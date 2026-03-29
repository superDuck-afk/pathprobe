"""Console output module — scan progress and summary display."""

from __future__ import annotations

from typing import Dict, List

from pathprobe.core.types import Finding, ScanTarget, TargetInfo
from pathprobe.core.config import (
    BANNER, BOLD, R, G, Y, C, M, B, W, DIM, RST,
)
from pathprobe.scanner.result_collector import ResultCollector


def print_banner():
    print(BANNER)


def print_legal_notice():
    print(f"\n{R}{BOLD}[!] LEGAL NOTICE{RST}: Authorized penetration testing ONLY.")
    print(f"{R}    Unauthorized use is illegal. Ensure written permission.{RST}\n")


def print_scan_config(
    url: str,
    params: List[str],
    total_payloads: int,
    method: str,
    threads: int,
    rate: float | None,
    retries: int,
    post_modes: List[str],
    waf_bypass: str | None,
    ip_spoof: bool,
    wordlist: str | None,
    aggressive: bool,
    verify: bool,
):
    rate_str = f"{rate:.1f} req/s" if rate else "unlimited"
    print(f"\n{BOLD}{W}[*] Target      :{RST} {url}")
    print(f"{BOLD}{W}[*] Params      :{RST} {', '.join(params)}")
    print(f"{BOLD}{W}[*] Method      :{RST} {method}")
    print(f"{BOLD}{W}[*] Concurrency :{RST} {threads}")
    print(f"{BOLD}{W}[*] Rate        :{RST} {rate_str}")
    print(f"{BOLD}{W}[*] Retries     :{RST} {retries}")
    print(f"{BOLD}{W}[*] POST modes  :{RST} {', '.join(post_modes) if post_modes else 'disabled'}")
    print(f"{BOLD}{W}[*] WAF bypass  :{RST} {waf_bypass or 'disabled'}")
    print(f"{BOLD}{W}[*] IP spoofing :{RST} {'enabled' if ip_spoof else 'disabled'}")
    print(f"{BOLD}{W}[*] Aggressive  :{RST} {'enabled' if aggressive else 'disabled'}")
    print(f"{BOLD}{W}[*] Verify      :{RST} {'enabled' if verify else 'disabled'}")
    if wordlist:
        print(f"{BOLD}{W}[*] Wordlist    :{RST} {wordlist}")
    print(f"\n{'─'*60}")


def print_param_summary(targets: List[ScanTarget]):
    hi = sum(1 for t in targets if t.priority == "HIGH")
    md = sum(1 for t in targets if t.priority == "MEDIUM")
    lo = sum(1 for t in targets if t.priority == "LOW")
    sk = sum(1 for t in targets if t.priority == "SKIP")
    print(f"\n{BOLD}[*] Parameter priority summary:{RST}")
    print(f"    {R}HIGH:{RST}   {hi}")
    print(f"    {Y}MEDIUM:{RST} {md}")
    print(f"    {DIM}LOW:{RST}    {lo}")
    if sk:
        print(f"    {DIM}SKIP:{RST}   {sk}")


def print_baseline(status: int, length: int, elapsed: float):
    print(f"{DIM}    Status: {status}  |  Length: {length}  "
          f"|  Time: {elapsed}s{RST}")


def print_scan_complete(
    collector: ResultCollector,
    elapsed_total: float,
):
    print(f"\n{'─'*60}")
    print(f"\n{BOLD}[+] Scan complete{RST}  —  "
          f"{collector.total_requests} requests  |  "
          f"{G}{collector.count} finding(s){RST}  |  "
          f"{elapsed_total:.2f}s\n")

    if not collector.count:
        print(f"{Y}[!] No vulnerabilities found.{RST}")
        return

    # Print scored summary table
    summary = collector.summary()
    sev = summary["severity_counts"]
    print(f"{BOLD}[*] Severity breakdown:{RST}")
    for s, c in sev.items():
        if c > 0:
            sc = R if s == "CRITICAL" else Y if s == "HIGH" else M if s == "MEDIUM" else DIM
            print(f"    {sc}{s:<10}{RST} {c}")

    verified_n = summary["verified_count"]
    print(f"\n{BOLD}[*] Verified findings:{RST} {verified_n}/{collector.count}")

    if summary["waf_techniques_hit"]:
        print(f"{BOLD}[*] WAF bypasses used:{RST} "
              f"{', '.join(summary['waf_techniques_hit'])}")

    # Top findings by score
    print(f"\n{BOLD}[*] Top findings:{RST}")
    for i, f in enumerate(collector.findings[:10], 1):
        bar = '█' * (f.confidence_score // 5) + '░' * (20 - f.confidence_score // 5)
        verified_mark = f"{G}✓{RST}" if f.verified else f"{DIM}?{RST}"
        sev = f.severity
        sc = (R if sev == "CRITICAL" else Y if sev == "HIGH" else M)
        print(f"  [{f.confidence_score:3d}] {sc}{sev:<8}{RST} "
              f"{bar}  {verified_mark} "
              f"param={BOLD}{f.param}{RST}  {G}{f.payload[:45]}{RST}")
