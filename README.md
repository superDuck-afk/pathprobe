<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10%2B-brightgreen?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge" alt="Platform">
</p>

<h1 align="center">🔍 PathProbe v3.0</h1>
<p align="center"><b>Advanced Adaptive Path Traversal Testing Framework</b></p>
<p align="center"><i>Two-phase fuzzing · Combinatorial payloads · WAF bypass · Auto PoC generation</i></p>

---

## ⚡ What is PathProbe?

PathProbe is an **offensive security tool** designed for authorized penetration testers and bug bounty hunters to detect **path traversal (directory traversal / LFI)** vulnerabilities in web applications.

Unlike basic scanners that rely on static wordlists and simple `../` payloads, PathProbe uses:

- **Adaptive two-phase fuzzing** — light discovery scan first, then deep exploitation only on promising parameters
- **Combinatorial payload generation** — dynamically combines depth × encoding × traversal variant × target file × suffix
- **Smart parameter targeting** — detects file-like values in parameters (not just name-matching)
- **7-layer response analysis** — signature matching, error detection, structural fingerprints, base64 PHP detection, similarity scoring, content-type anomaly, and size anomaly
- **Automatic re-verification** — reduces false positives by re-testing hits
- **OS/server fingerprinting** — filters payloads based on detected target stack

---

## 📦 Installation

### Prerequisites

- **Python 3.10+**
- **pip** (Python package manager)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/pathprobe.git
cd pathprobe

# Install dependencies
pip install -r requirements.txt
```

### Manual Install (no git)

```bash
# Download and extract, then:
cd pathprobe
pip install -r requirements.txt
```

### Verify Installation

```bash
python -m pathprobe --help
```

---

## 🚀 Quick Start

### Basic Scan

```bash
python -m pathprobe http://target.com/page.php -p file
```

### Scan Multiple Parameters

```bash
python -m pathprobe http://target.com/download -p file,path,doc,template
```

### Full Recon + Adaptive Scan

```bash
python -m pathprobe http://target.com --crawl 3 -p file
```

### With WAF Bypass

```bash
python -m pathprobe http://target.com -p file --waf-bypass all --waf-ip-spoof
```

---

## 📖 Usage

```
usage: pathprobe [-h] [-p PARAM] [-m {GET,POST,BOTH}] [--aggressive]
                 [--no-verify] [--post-mode POST_MODE]
                 [--json-template JSON_TEMPLATE] [--filename-inject]
                 [--waf-bypass WAF_BYPASS] [--waf-ip-spoof] [--crawl DEPTH]
                 [--max-urls N] [--wordlist FILE]
                 [--zipslip-generate PATH] [--zipslip-test UPLOAD_URL]
                 [--zipslip-param ZIPSLIP_PARAM] [--threads N] [--rate RPS]
                 [--retries N] [-H HEADERS] [-c COOKIES] [--timeout TIMEOUT]
                 [--no-ssl-verify] [--report REPORT] [-v]
                 url
```

### Core Options

| Option | Default | Description |
|--------|---------|-------------|
| `url` | *(required)* | Target URL to test |
| `-p, --param` | `file` | Parameter(s) to test (comma-separated) |
| `-m, --method` | `GET` | HTTP method: `GET`, `POST`, or `BOTH` |
| `--aggressive` | off | Enable aggressive PHP wrappers (`php://input`, `data://`, `expect://`) |
| `--no-verify` | off | Skip re-verification (faster but more false positives) |
| `-v, --verbose` | off | Show every request in output |

### POST Fuzzing

| Option | Description |
|--------|-------------|
| `--post-mode` | POST body format(s): `form`, `json`, `xml`, `multipart`, or `all` |
| `--json-template` | Base JSON template, e.g. `'{"action":"view"}'` |
| `--filename-inject` | Inject payload into multipart `filename` field |

### WAF Bypass

| Option | Description |
|--------|-------------|
| `--waf-bypass` | Technique(s): `case_variation`, `insert_null`, `path_comment`, `tab_newline`, `double_slash`, `semicolon`, `hash_bypass`, `overlong_dot`, or `all` |
| `--waf-ip-spoof` | Add spoofing headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, etc.) |

### Recon & Crawling

| Option | Default | Description |
|--------|---------|-------------|
| `--crawl DEPTH` | off | BFS crawl to discover endpoints and parameters |
| `--max-urls N` | `1000` | Maximum URLs to crawl |
| `--wordlist FILE` | none | External payload wordlist (one per line) |

### ZipSlip Testing

| Option | Description |
|--------|-------------|
| `--zipslip-generate PATH` | Generate malicious ZIP/TAR archive locally |
| `--zipslip-test URL` | Upload malicious archive and test for ZipSlip |
| `--zipslip-param` | Form field name for upload (default: `file`) |

### Performance

| Option | Default | Description |
|--------|---------|-------------|
| `--threads N` | `20` | Concurrent requests (max: 100) |
| `--rate RPS` | unlimited | Rate limit (requests per second) |
| `--retries N` | `2` | Retry count on network errors |
| `--timeout` | `10` | HTTP timeout in seconds |

### Request Options

| Option | Description |
|--------|-------------|
| `-H, --headers` | Extra headers (semicolon-separated): `"Auth:Bearer xyz; X-Custom:val"` |
| `-c, --cookies` | Cookie string: `"session=abc123; token=xyz"` |
| `--no-ssl-verify` | Disable SSL certificate verification |

### Output

| Option | Default | Description |
|--------|---------|-------------|
| `--report` | `txt` | Report format(s): `txt`, `json`, `csv`, `html`, or `all` |

---

## 🎯 Usage Examples

### 1. Standard Path Traversal Scan

```bash
python -m pathprobe "http://vulnerable-app.com/read?file=report.pdf" -p file -v
```

### 2. Authenticated Scan with Cookies

```bash
python -m pathprobe "http://app.com/dashboard?doc=help.html" \
    -p doc \
    -c "PHPSESSID=abc123def456" \
    -H "Authorization:Bearer eyJ..."
```

### 3. POST Body Fuzzing (JSON API)

```bash
python -m pathprobe "http://api.example.com/v1/files" \
    -p filepath \
    -m POST \
    --post-mode json \
    --json-template '{"action":"read","format":"raw"}'
```

### 4. Full WAF Bypass + IP Spoofing

```bash
python -m pathprobe "http://waf-protected.com/view?page=about" \
    -p page \
    --waf-bypass all \
    --waf-ip-spoof \
    --threads 10 \
    --rate 5
```

### 5. Auto-Discovery with Crawling

```bash
python -m pathprobe "http://target.com" \
    --crawl 3 \
    --max-urls 500 \
    -p file,path,doc,template,page \
    --report all
```

### 6. Aggressive Mode (PHP LFI → Source Disclosure)

```bash
python -m pathprobe "http://php-app.com/index.php?page=home" \
    -p page \
    --aggressive \
    --report json
```

### 7. ZipSlip Archive Generation

```bash
# Generate malicious ZIP for manual testing
python -m pathprobe "http://any.com" --zipslip-generate evil.zip

# Generate malicious TAR
python -m pathprobe "http://any.com" --zipslip-generate evil.tar.gz
```

### 8. High-Performance Scan with Rate Limiting

```bash
python -m pathprobe "http://target.com/api/download?f=doc.pdf" \
    -p f \
    --threads 50 \
    --rate 20 \
    --retries 3 \
    --timeout 15
```

### 9. External Wordlist

```bash
python -m pathprobe "http://target.com/load?path=main" \
    -p path \
    --wordlist /path/to/custom-lfi-payloads.txt
```

### 10. Multiple POST Formats at Once

```bash
python -m pathprobe "http://target.com/upload" \
    -p file \
    -m BOTH \
    --post-mode all \
    --filename-inject
```

---

## 🏗️ Architecture

PathProbe v3.0 is built as a modular pipeline:

```
┌──────────┐    ┌─────────────┐    ┌───────────┐    ┌──────────┐
│  Recon   │───>│ Fingerprint │───>│ ParamScore│───>│ Discovery│
│ (crawl)  │    │ (OS/server) │    │ (value +  │    │ (light   │
│          │    │             │    │ behavior) │    │ fuzzing) │
└──────────┘    └─────────────┘    └───────────┘    └────┬─────┘
                                                         │
                                                    ┌────▼─────┐
                                              ┌─────│ Adaptive │
                                              │     │ Expansion│
                                              │     └────┬─────┘
                                              │          │
                                         ┌────▼──────────▼─────┐
                                         │   Exploitation      │
                                         │   (deep fuzzing on  │
                                         │   promising params) │
                                         └────────┬────────────┘
                                                  │
                                    ┌─────────────▼──────────────┐
                                    │  Verify → Score → Report   │
                                    └────────────────────────────┘
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `core/transport.py` | Async HTTP engine (aiohttp) — the **only** async module |
| `core/types.py` | Shared dataclasses (`PayloadMeta`, `Response`, `Finding`, etc.) |
| `core/config.py` | All constants, signatures, thresholds (data only, no logic) |
| `modules/payload_engine.py` | Combinatorial payload generator with adaptive expansion |
| `modules/waf_bypass.py` | Compositional encoders and WAF transforms |
| `modules/response_analyzer.py` | 7-layer detection engine (**pure functions**) |
| `modules/fingerprinter.py` | OS/server/framework detection from response characteristics |
| `modules/param_analyzer.py` | Value-based + behavioral parameter scoring |
| `modules/verifier.py` | Re-verification to reduce false positives |
| `modules/poc_generator.py` | Auto-generates curl commands and Python PoC scripts |
| `modules/zipslip.py` | Malicious archive generation and upload testing |
| `scanner/engine.py` | Two-phase adaptive scan orchestrator |
| `scanner/result_collector.py` | Central findings with dedup, scoring, short-circuit |
| `recon/crawler.py` | BFS web crawler |
| `recon/param_extractor.py` | Parameter discovery from URLs, forms, JSON |
| `reporting/console.py` | Terminal output formatting |
| `reporting/reporter.py` | File reports (JSON, HTML, CSV, TXT) |

---

## 🧠 How Detection Works

PathProbe uses a **7-layer detection engine**, each layer adding confidence:

### Layer 1: Content Signatures
Regex patterns matching known file contents (`root:x:0:0`, `[extensions]`, `DB_PASSWORD=`, SSH keys, etc.)

### Layer 2: Error-Based Detection
Server error messages proving traversal was attempted (`No such file or directory`, `failed to open stream`, `FileNotFoundException`, etc.)

### Layer 3: Structural Fingerprints
Detects file structures without relying on specific content:
- `/etc/passwd` structure: 3+ lines with `user:x:uid:gid:` format
- `.env` structure: 3+ `KEY=VALUE` lines
- INI structure: 2+ `[section]` headers
- XML/JSON config detection

### Layer 4: Base64 PHP Source Detection
When `php://filter` wrappers return base64-encoded source code, this layer decodes and confirms PHP markers — **zero false positive rate**.

### Layer 5: Similarity Scoring
Compares response to baseline using:
- **SequenceMatcher** for responses < 16KB
- **SimHash** (Jaccard on chunk hashes) for larger responses — O(n) instead of O(n²)

### Layer 6: Content-Type Anomaly
Detects when the response content-type changes (e.g., `text/html` → `text/plain`) — strong signal of file inclusion.

### Layer 7: Size Anomaly
Flags responses significantly larger than baseline (>1.5×).

### Confidence Scoring (0–100)

Each finding gets a composite score:

| Signal | Points |
|--------|--------|
| CRITICAL signature match | +40 |
| HIGH signature match | +30 |
| MEDIUM signature match | +20 |
| Error-based detection | +15 |
| Similarity < 0.50 | +15 |
| Similarity < 0.70 | +10 |
| Content-type changed | +10 |
| Size anomaly | +5 |
| Verified (re-test passed) | +15 |
| Single hit out of 20+ payloads | -10 |

---

## 🛡️ WAF Bypass Techniques

PathProbe includes **8 bypass transforms** that **compose** (combine with each other):

| Technique | Example | Description |
|-----------|---------|-------------|
| `case_variation` | `..%2F..%2FEtC%2FpAsSwD` | Randomized casing on path segments |
| `insert_null` | `..%00/..%00/etc/passwd` | Null bytes to break WAF pattern matching |
| `path_comment` | `.%09./` | Tab injection between path components |
| `tab_newline` | `..%0a/` | Newline characters in traversal sequences |
| `double_slash` | `.././//etc//passwd` | Extra slashes to confuse normalization |
| `semicolon` | `..;/..;/etc/passwd` | Tomcat/Jetty path-parameter trick |
| `hash_bypass` | `../%23/../etc/passwd` | Fragment identifier abuse |
| `overlong_dot` | `%c0%ae%c0%ae/etc/passwd` | Overlong UTF-8 for dot character |

**Key improvement over v2**: Transforms are now **chained** — e.g., `case_variation+insert_null` applies both simultaneously. With `--waf-bypass all`, PathProbe tests individual transforms AND pairwise combinations.

---

## 📊 Report Formats

### JSON Report
```bash
python -m pathprobe http://target.com -p file --report json
```
Machine-readable output with full metadata, PoC commands, and confidence scores.

### HTML Report
```bash
python -m pathprobe http://target.com -p file --report html
```
Dark-themed interactive report with expandable evidence snippets and severity badges.

### CSV Report
```bash
python -m pathprobe http://target.com -p file --report csv
```
Spreadsheet-compatible format for data analysis.

### TXT Report
```bash
python -m pathprobe http://target.com -p file --report txt
```
Plain-text report with PoC curl commands.

### All Formats
```bash
python -m pathprobe http://target.com -p file --report all
```

---

## 📁 Project Structure

```
pathprobe/
├── README.md                 # This file
├── LICENSE                   # MIT License
├── requirements.txt          # Python dependencies
├── setup.py                  # Package installer
├── .gitignore                # Git ignore rules
├── CONTRIBUTING.md           # Contribution guidelines
├── docs/
│   └── EXAMPLES.md           # Extended usage examples
├── pathprobe/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── transport.py
│   │   └── types.py
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── fingerprinter.py
│   │   ├── param_analyzer.py
│   │   ├── payload_engine.py
│   │   ├── poc_generator.py
│   │   ├── response_analyzer.py
│   │   ├── verifier.py
│   │   ├── waf_bypass.py
│   │   └── zipslip.py
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   └── result_collector.py
│   ├── recon/
│   │   ├── __init__.py
│   │   ├── crawler.py
│   │   └── param_extractor.py
│   └── reporting/
│       ├── __init__.py
│       ├── console.py
│       └── reporter.py
└── legacy/
    └── path_probe_tester_v2.py   # Original v2 tool (preserved)
```

---

## ⚠️ Legal Disclaimer

> **PathProbe is designed for authorized security testing only.**
>
> You must have **explicit written permission** from the system owner before running this tool against any target. Unauthorized use of this tool against systems you do not own or have permission to test is **illegal** and may violate computer crime laws in your jurisdiction.
>
> The authors assume no liability for misuse of this software.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Adding new payload techniques
- Implementing new detection signatures
- Submitting bug reports
- Code style and testing requirements

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — Path traversal methodology
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/file-path-traversal) — LFI/path traversal labs
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal) — Payload references
- [SecLists](https://github.com/danielmiessler/SecLists) — Wordlist resources
- [Snyk ZipSlip Research](https://security.snyk.io/research/zip-slip-vulnerability) — Archive traversal methodology
