# Changelog

All notable changes to PathProbe are documented here.

## [3.0.0] - 2026-03-29

### 🚀 Complete Rewrite

PathProbe v3.0 is a ground-up modular rewrite of the original v2 single-file scanner.

### Added

- **Adaptive two-phase fuzzing** — discovery (light) then exploitation (deep) on promising parameters only
- **Combinatorial payload engine** — dynamically generates payloads by combining depth × encoding × traversal variant × target file × suffix
- **Value-based parameter detection** — analyzes parameter VALUES (not just names) to identify file-related inputs
- **7-layer response analysis** — regex signatures, error detection, structural fingerprints, base64 PHP detection, similarity scoring, content-type anomaly, size anomaly
- **OS/server fingerprinting** — detects target OS, web server, framework, and language; filters payloads accordingly
- **Compositional WAF bypass** — 8 transforms that compose (chain) with each other, not just individual application
- **PHP wrapper payloads** — `php://filter/convert.base64-encode/resource=` in core; write primitives behind `--aggressive` flag
- **ZipSlip testing** — generate malicious ZIP/TAR archives with traversal entries and symlinks
- **Finding re-verification** — re-sends triggering payloads to confirm consistency and reduce false positives
- **0-100 confidence scoring** — composite score based on signature weight, error detection, similarity, verification
- **Auto PoC generation** — curl commands and standalone Python scripts for every finding
- **Per-URL baseline caching** — single baseline fetch per URL instead of per-parameter
- **Async transport (aiohttp)** — connection pooling, semaphore backpressure, cooperative cancellation
- **Central result collector** — canonical deduplication, per-param short-circuit after 3 HIGH findings
- **Path extraction from errors** — extracts disclosed server paths from error messages
- **Server-specific payloads** — Tomcat `..;/`, IIS `..%5c`, PHP wrappers, Spring double-encode
- **`--zipslip-generate`** — standalone command to create malicious archives for manual testing

### Changed

- Architecture: single 1462-line file → 25-file modular package with 6 sub-packages
- Payload generation: static ~120 payloads → dynamic combinatorial generator (hundreds in discovery, thousands in exploitation)
- WAF bypass: 7 individual transforms → 8 composable transforms with pairwise chaining
- Similarity scoring: O(n²) SequenceMatcher only → SimHash for >16KB responses
- Parameter scoring: name-only hints → value regex + behavioral probing + calibrated thresholds
- Threading: `ThreadPoolExecutor` → `asyncio` + `aiohttp` with proper backpressure
- Default concurrency: 5 → 20 threads

### Removed

- Static parameter name filtering (replaced by value-based + behavioral detection)
- `archive_traversal` payload category (replaced by real ZipSlip module)
- `truncation` payload category (replaced by adaptive depth escalation)
- Graphql POST mode (deferred — needs proper variable handling)

## [2.0.0] - 2026-03-29

### Added (v2 — original)

- POST body fuzzing (form, JSON, XML, multipart, GraphQL)
- WAF bypass engine (7 techniques)
- BFS crawler with parameter auto-discovery
- Behavioral parameter prioritization
- Error-based detection signatures
- Response similarity scoring
- External wordlist support
- Rate limiting and retry logic
- HTML/JSON/CSV/TXT reports
