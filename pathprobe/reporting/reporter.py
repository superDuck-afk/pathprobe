"""File-based report generation — JSON, CSV, HTML, TXT.

All formats include PoC commands and confidence scores.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from typing import Dict, List

from pathprobe.core.types import Finding
from pathprobe.core.config import G, RST
from pathprobe.scanner.result_collector import ResultCollector
from pathprobe.modules.poc_generator import PoCGenerator


def _ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def generate_reports(
    collector: ResultCollector,
    target_url: str,
    formats: List[str],
) -> List[str]:
    """Generate reports in requested formats.  Returns list of filenames."""
    if not collector.count:
        return []

    base = f"pathprobe_report_{_ts()}"
    files_written: List[str] = []
    findings = collector.findings
    summary = collector.summary()

    if "json" in formats or "all" in formats:
        fname = f"{base}.json"
        with open(fname, "w") as f:
            json.dump({
                "tool": "PathProbe",
                "version": "3.0.0",
                "target": target_url,
                "scan_time": datetime.now().isoformat(),
                "total_findings": collector.count,
                "summary": summary,
                "findings": [fd.to_dict() for fd in findings],
            }, f, indent=2)
        files_written.append(fname)
        print(f"{G}[+] JSON  → {fname}{RST}")

    if "csv" in formats or "all" in formats:
        fname = f"{base}.csv"
        fields = [
            "param", "payload", "url", "status", "response_length",
            "elapsed", "confidence", "confidence_score", "severity",
            "verified", "post_mode", "waf_technique", "timestamp",
            "signatures_summary", "curl_poc",
        ]
        with open(fname, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for fd in findings:
                row = {
                    "param": fd.param,
                    "payload": fd.payload,
                    "url": fd.url,
                    "status": fd.status,
                    "response_length": fd.response_length,
                    "elapsed": fd.elapsed,
                    "confidence": fd.confidence,
                    "confidence_score": fd.confidence_score,
                    "severity": fd.severity,
                    "verified": fd.verified,
                    "post_mode": fd.post_mode,
                    "waf_technique": fd.waf_technique,
                    "timestamp": fd.timestamp,
                    "signatures_summary": "; ".join(
                        f"{s.description} [{s.severity}]"
                        for s in fd.signatures
                    ),
                    "curl_poc": fd.curl_poc,
                }
                w.writerow(row)
        files_written.append(fname)
        print(f"{G}[+] CSV   → {fname}{RST}")

    if "txt" in formats or "all" in formats:
        fname = f"{base}.txt"
        with open(fname, "w") as f:
            f.write(_build_txt(findings, summary, target_url))
        files_written.append(fname)
        print(f"{G}[+] TXT   → {fname}{RST}")

    if "html" in formats or "all" in formats:
        fname = f"{base}.html"
        with open(fname, "w") as f:
            f.write(_build_html(findings, summary, target_url))
        files_written.append(fname)
        print(f"{G}[+] HTML  → {fname}{RST}")

    return files_written


# ─────────────────────────────────────────────
#  TXT format
# ─────────────────────────────────────────────

def _build_txt(
    findings: List[Finding],
    summary: Dict,
    target_url: str,
) -> str:
    lines = [
        "=" * 70,
        "  PathProbe v3.0 - Path Traversal Vulnerability Report",
        "=" * 70,
        f"  Target    : {target_url}",
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Findings  : {len(findings)}",
        f"  Verified  : {summary.get('verified_count', 0)}",
        "=" * 70, "",
        "SUMMARY", "-" * 40,
    ]
    for sev, cnt in summary["severity_counts"].items():
        if cnt:
            lines.append(f"  {sev:<12}: {cnt}")
    lines += [
        f"  Params hit    : {', '.join(summary['affected_params'])}",
        f"  POST modes hit: {', '.join(summary['post_modes_hit'])}",
        f"  WAF bypasses  : {', '.join(summary['waf_techniques_hit']) or 'none'}",
        "",
    ]

    poc = PoCGenerator()
    for i, f in enumerate(findings, 1):
        lines += [
            f"FINDING #{i}  [Score: {f.confidence_score}/100]",
            "-" * 40,
            f"  Parameter   : {f.param}",
            f"  Payload     : {f.payload}",
            f"  Severity    : {f.severity}",
            f"  Confidence  : {f.confidence} ({f.confidence_score}/100)",
            f"  Verified    : {'YES' if f.verified else 'No'}",
            f"  POST Mode   : {f.post_mode}",
            f"  WAF Bypass  : {f.waf_technique}",
            f"  URL         : {f.url}",
            f"  Status      : {f.status}",
            f"  Resp Length : {f.response_length}",
            f"  Timestamp   : {f.timestamp}",
        ]
        if f.signatures:
            lines.append("  Signatures  :")
            for s in f.signatures:
                lines.append(f"    * [{s.severity}] {s.description} (OS: {s.os})")
        if f.disclosed_paths:
            lines.append(f"  Disclosed paths: {', '.join(f.disclosed_paths)}")
        lines += [
            "",
            "  PoC (curl):",
            f"    {f.curl_poc}",
            "",
            f"  Evidence    :",
            f"    {f.evidence_snippet[:300]}",
            "",
        ]

    lines += [
        "=" * 70,
        "  PathProbe v3.0 | For authorized security testing only",
        "=" * 70,
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────
#  HTML format
# ─────────────────────────────────────────────

def _build_html(
    findings: List[Finding],
    summary: Dict,
    target_url: str,
) -> str:
    import html as html_mod

    sev_col = {
        "CRITICAL": "#ff4444", "HIGH": "#ff8800",
        "MEDIUM": "#ffcc00", "LOW": "#44aaff",
    }
    waf_hits = ", ".join(summary["waf_techniques_hit"]) or "—"
    pm_hits = ", ".join(summary["post_modes_hit"]) or "—"

    sev_boxes = "".join(
        f'<div class="sev-box" style="border-color:{sev_col.get(s,"#888")}">'
        f'<div class="sev-count" style="color:{sev_col.get(s,"#888")}">{c}</div>'
        f'<div class="sev-label">{s}</div></div>'
        for s, c in summary["severity_counts"].items()
    )

    rows = ""
    for i, f in enumerate(findings, 1):
        sigs_html = "".join(
            f'<span class="badge badge-{s.severity.lower()}">{s.severity}</span> '
            f'{html_mod.escape(s.description)} (OS: {s.os})<br>'
            for s in f.signatures
        ) or "<em>Behavioral detection</em>"

        ver_icon = "✓" if f.verified else "?"
        waf_tag = (f'<span class="tag tag-waf">WAF:{f.waf_technique}</span>'
                   if f.waf_technique != "none" else "")
        score_bar = '█' * (f.confidence_score // 5) + '░' * (20 - f.confidence_score // 5)

        rows += f"""
        <div class="finding">
          <div class="finding-header">
            <span class="finding-num">#{i}</span>
            <span class="finding-score">[{f.confidence_score}/100] {score_bar}</span>
            <span class="finding-conf conf-{f.confidence.lower()}">{f.confidence}</span>
            <span class="tag tag-ver">{ver_icon}</span>
            <span class="tag tag-post">{f.post_mode}</span>{waf_tag}
            <code class="payload">{html_mod.escape(f.payload[:80])}</code>
          </div>
          <table class="details">
            <tr><td>Parameter</td><td><code>{html_mod.escape(f.param)}</code></td></tr>
            <tr><td>Severity</td><td>{f.severity}</td></tr>
            <tr><td>Status</td><td>{f.status}</td></tr>
            <tr><td>Response Len</td><td>{f.response_length} bytes</td></tr>
            <tr><td>Similarity</td><td>{f.similarity_score:.4f}</td></tr>
            <tr><td>Timestamp</td><td>{f.timestamp}</td></tr>
            <tr><td>Signatures</td><td>{sigs_html}</td></tr>
          </table>
          <details><summary>PoC (curl)</summary>
            <pre class="evidence">{html_mod.escape(f.curl_poc)}</pre>
          </details>
          <details><summary>Evidence Snippet</summary>
            <pre class="evidence">{html_mod.escape(f.evidence_snippet[:500])}</pre>
          </details>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>PathProbe v3.0 Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:2rem}}
h1{{color:#58a6ff;font-size:2rem;margin-bottom:.25rem}}
.meta{{color:#8b949e;margin-bottom:1rem;font-size:.85rem}}
.scan-meta{{display:flex;gap:1rem;margin-bottom:2rem;font-size:.8rem;color:#8b949e;flex-wrap:wrap}}
.scan-meta span{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:.4rem .8rem}}
.summary{{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}}
.sev-box{{border:2px solid;border-radius:8px;padding:1rem 1.5rem;text-align:center;min-width:100px}}
.sev-count{{font-size:2rem;font-weight:bold}}
.sev-label{{font-size:.75rem;color:#8b949e;margin-top:.25rem}}
.finding{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:1rem;overflow:hidden}}
.finding-header{{background:#21262d;padding:.75rem 1rem;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}}
.finding-num{{color:#8b949e;font-size:.8rem}}
.finding-score{{color:#58a6ff;font-size:.75rem;font-family:monospace}}
.payload{{background:#0d1117;padding:.2rem .5rem;border-radius:4px;color:#79c0ff;font-size:.82rem}}
.conf-high,.badge-critical{{background:#ff4444;color:#fff;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:bold}}
.conf-medium,.badge-high{{background:#ff8800;color:#fff;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:bold}}
.conf-low,.badge-medium{{background:#ffcc00;color:#000;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:bold}}
.badge-low{{background:#44aaff;color:#fff;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:bold}}
.tag{{padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:bold}}
.tag-post{{background:#1f6feb;color:#fff}}
.tag-waf{{background:#8957e5;color:#fff}}
.tag-ver{{background:#238636;color:#fff}}
.details{{width:100%;padding:1rem;border-collapse:collapse;font-size:.85rem}}
.details td{{padding:.3rem 1rem;vertical-align:top}}
.details td:first-child{{color:#8b949e;width:140px}}
details{{padding:.5rem 1rem 1rem}}
summary{{cursor:pointer;color:#58a6ff;margin-bottom:.5rem}}
.evidence{{background:#0d1117;padding:1rem;border-radius:4px;font-size:.75rem;white-space:pre-wrap;color:#e3b341;overflow-x:auto}}
footer{{margin-top:3rem;color:#8b949e;font-size:.75rem;text-align:center}}
</style></head><body>
<h1>🔍 PathProbe v3.0 Report</h1>
<div class="meta">Target: {html_mod.escape(target_url)} &nbsp;|&nbsp; Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; {len(findings)} findings &nbsp;|&nbsp; {summary.get('verified_count',0)} verified</div>
<div class="scan-meta">
  <span>📡 POST modes: {pm_hits}</span>
  <span>🛡️ WAF bypasses: {waf_hits}</span>
  <span>🎯 Params: {", ".join(summary["affected_params"])}</span>
</div>
<div class="summary">{sev_boxes}</div>
<h2 style="color:#8b949e;margin-bottom:1rem;font-size:.9rem;text-transform:uppercase;letter-spacing:2px">Findings</h2>
{rows}
<footer>PathProbe v3.0 | For authorized security testing only</footer>
</body></html>"""
