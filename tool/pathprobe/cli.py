"""CLI argument parser for PathProbe v3.0."""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pathprobe",
        description=(
            "PathProbe v3.0 — Adaptive Path Traversal Testing Framework\n"
            "For authorized security testing only."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # ── Target ───────────────────────────────────────────────────
    p.add_argument("url", help="Target URL")
    p.add_argument(
        "-p", "--param", default="file",
        help="Parameter(s) to test, comma-separated (default: file)",
    )
    p.add_argument(
        "-m", "--method", default="GET",
        choices=["GET", "POST", "BOTH"],
        help="HTTP method: GET | POST | BOTH (default: GET)",
    )

    # ── Scan control ─────────────────────────────────────────────
    p.add_argument(
        "--aggressive", action="store_true",
        help="Enable aggressive PHP wrappers (php://input, data://, expect://)",
    )
    p.add_argument(
        "--no-verify", dest="no_verify", action="store_true",
        help="Skip re-verification of findings (faster but more FPs)",
    )

    # ── POST fuzzing ─────────────────────────────────────────────
    p.add_argument(
        "--post-mode", dest="post_mode", default=None,
        help="POST body format(s) (comma-sep or 'all'):\n"
             "  form, json, xml, multipart",
    )
    p.add_argument(
        "--json-template", dest="json_template", default=None,
        help='Base JSON template for json mode (e.g. \'{"action":"view"}\')',
    )
    p.add_argument(
        "--filename-inject", dest="filename_inject", action="store_true",
        help="Inject into multipart filename field (file upload testing)",
    )

    # ── WAF bypass ───────────────────────────────────────────────
    p.add_argument(
        "--waf-bypass", dest="waf_bypass", default=None,
        help="WAF bypass technique(s) (comma-sep or 'all'):\n"
             "  case_variation, insert_null, path_comment,\n"
             "  tab_newline, double_slash, semicolon,\n"
             "  hash_bypass, overlong_dot",
    )
    p.add_argument(
        "--waf-ip-spoof", dest="waf_ip_spoof", action="store_true",
        help="Add IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.)",
    )

    # ── Recon / crawl ────────────────────────────────────────────
    p.add_argument(
        "--crawl", type=int, default=None, metavar="DEPTH",
        help="Crawl target up to DEPTH levels and auto-discover parameters",
    )
    p.add_argument(
        "--max-urls", dest="max_urls", type=int, default=1000, metavar="N",
        help="Maximum URLs to crawl (default: 1000)",
    )

    # ── Wordlist ─────────────────────────────────────────────────
    p.add_argument(
        "--wordlist", default=None, metavar="FILE",
        help="External payload wordlist (one payload per line).\n"
             "  Blank lines and lines starting with '#' are skipped.",
    )

    # ── ZipSlip ──────────────────────────────────────────────────
    p.add_argument(
        "--zipslip-generate", dest="zipslip_generate", default=None,
        metavar="PATH",
        help="Generate malicious ZIP archive to PATH (local only, no upload)",
    )
    p.add_argument(
        "--zipslip-test", dest="zipslip_test", default=None,
        metavar="UPLOAD_URL",
        help="Upload malicious archive to UPLOAD_URL and test for ZipSlip",
    )
    p.add_argument(
        "--zipslip-param", dest="zipslip_param", default="file",
        help="Form field name for ZipSlip upload (default: file)",
    )

    # ── Performance ──────────────────────────────────────────────
    p.add_argument(
        "--threads", type=int, default=20, metavar="N",
        help="Concurrent requests (default: 20, max: 100)",
    )
    p.add_argument(
        "--rate", type=float, default=None, metavar="RPS",
        help="Max requests per second (e.g. 10.0)",
    )
    p.add_argument(
        "--retries", type=int, default=2, metavar="N",
        help="Retry count on network/timeout errors (default: 2)",
    )

    # ── Request ──────────────────────────────────────────────────
    p.add_argument(
        "-H", "--headers",
        help='Extra headers (semicolon-sep, e.g. "X-Token:abc; Accept:text/html")',
    )
    p.add_argument("-c", "--cookies", help="Cookies string")
    p.add_argument(
        "--timeout", type=int, default=10,
        help="HTTP timeout seconds (default: 10)",
    )
    p.add_argument(
        "--no-ssl-verify", dest="no_ssl_verify", action="store_true",
        help="Disable SSL certificate verification",
    )

    # ── Output ───────────────────────────────────────────────────
    p.add_argument(
        "--report", default="txt",
        help="Report format(s): txt,json,csv,html,all (default: txt)",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output (show every request)",
    )

    return p
