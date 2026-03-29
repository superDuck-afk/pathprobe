# Contributing to PathProbe

Thanks for your interest in improving PathProbe! This guide covers how to contribute effectively.

---

## 🐛 Reporting Bugs

Open an issue with:
1. **Command used** (redact any sensitive target info)
2. **Expected behavior** vs **actual behavior**
3. **Error traceback** (if any)
4. **Python version** (`python --version`)
5. **OS** (Windows/Linux/macOS)

---

## 💡 Feature Requests

Open an issue with the `[FEATURE]` prefix. Include:
- **Use case**: What real-world scenario does this address?
- **Proposed behavior**: How should it work?
- **Alternatives considered**: What other approaches did you think of?

---

## 🔧 Development Setup

```bash
# Clone
git clone https://github.com/yourusername/pathprobe.git
cd pathprobe

# Create virtual environment
python -m venv venv
source venv/bin/activate    # Linux/macOS
venv\Scripts\activate       # Windows

# Install dependencies
pip install -r requirements.txt

# Verify
python -m pathprobe --help
```

---

## 📏 Code Style

- **Python 3.10+** features are allowed
- Use **type annotations** on all public functions
- All analysis functions must be **pure** (no side effects, no I/O)
- Only `core/transport.py` may contain `async`/`await` code
- Use docstrings (Google style) on all public classes and functions
- Keep lines under 100 characters where practical

---

## 🧩 Adding New Features

### Adding a New Payload Technique

1. **Edit `modules/payload_engine.py`**
2. Add the new traversal variant, separator, encoding, or suffix to the appropriate dict:
   ```python
   TRAVERSAL_VARIANTS = {
       "standard": "..",
       "your_new_variant": "..SOMETHING..",  # Add here
   }
   ```
3. The combinatorial generator will automatically include it in all phases

### Adding a New WAF Bypass Transform

1. **Edit `modules/waf_bypass.py`**
2. Create a new function:
   ```python
   def _your_transform(s: str) -> str:
       """Description of what this does."""
       return s.replace("../", "YOUR_BYPASS")
   ```
3. Register it in the `WAF_TRANSFORMS` dict:
   ```python
   WAF_TRANSFORMS = {
       ...,
       "your_transform": _your_transform,
   }
   ```
4. It will automatically be available via `--waf-bypass your_transform` and included in `--waf-bypass all`

### Adding a New Detection Signature

1. **Edit `core/config.py`**
2. Add to the `SIGNATURES` dict:
   ```python
   SIGNATURES = {
       ...,
       "your_signature": {
           "pattern": r"regex_pattern_here",
           "description": "Human-readable description",
           "severity": "CRITICAL",  # CRITICAL | HIGH | MEDIUM | LOW
           "os": "Linux",           # Linux | Windows | Any
       },
   }
   ```

### Adding a New Content Fingerprint

1. **Edit `modules/response_analyzer.py`**
2. Create a detection function:
   ```python
   def _is_your_structure(body: str) -> bool:
       """Return True if body matches your file structure."""
       return some_check(body)
   ```
3. Register in `CONTENT_FINGERPRINTS`:
   ```python
   CONTENT_FINGERPRINTS = {
       ...,
       "your_fingerprint": {
           "test": _is_your_structure,
           "severity": "HIGH",
           "description": "Your file type detected",
           "os": "Any",
       },
   }
   ```

### Adding a New Error Signature

1. **Edit `core/config.py`**
2. Add to `ERROR_SIGNATURES`:
   ```python
   ERROR_SIGNATURES = {
       ...,
       "your_error": r"regex_for_error_message",
   }
   ```

---

## 🏗️ Architecture Rules

These rules exist to keep the codebase maintainable:

1. **Async boundary is contained** — Only `core/transport.py` uses `async`. Everything else is synchronous.
2. **Analyzers are pure functions** — `analyse(response, baseline, meta) → AnalysisResult`. No side effects.
3. **Payload metadata is mandatory** — Every payload carries `PayloadMeta` with encoding, depth, target, technique.
4. **Findings go through `ResultCollector`** — Never `findings.append()` directly.
5. **Config is data only** — `core/config.py` has no functions or classes, just constants/dicts.
6. **Encoders/transforms are composable** — They are `str → str` functions. Use `compose()` to chain them.

---

## 📝 Pull Request Process

1. Fork the repo and create a feature branch from `main`
2. Add/update docstrings and type annotations
3. Test against a local vulnerable application (DVWA, WebGoat, etc.)
4. Update README.md if you added CLI options
5. Submit a PR with:
   - Clear description of what changed and why
   - Example command demonstrating the feature
   - Any relevant test output

---

## ⚖️ Ethical Guidelines

All contributions must:
- Be designed for **authorized testing only**
- Not include functionality that targets specific organizations
- Not include credentials, API keys, or identifying information
- Include appropriate warnings for dangerous features (like ZipSlip)

---

Thank you for helping make PathProbe better! 🔍
