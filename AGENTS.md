# Syck — Bug Bounty Secret Scanner

## What this repo is

A modular Python 3.10+ secret scanner for bug bounty hunting. Zero pip dependencies (stdlib only), ~250+ regex detection rules, Shannon entropy analysis, multi-layer decoder pipeline (base64/hex/unicode/url/gzip), JS string reconstruction, JSON-aware scanning, git history scanning, live secret validation, and a full recon pipeline (subfinder → httpx → katana/gau → download → syck).

| File/Dir | Purpose |
|---|---|
| `syck/` | Core package — scanner, rules, decoders, formatters, CLI, hunt pipeline, server |
| `syck.py` | Thin shim → `syck.cli.main()` |
| `syck-hunt.py` | Thin shim → `syck.hunt.cli.main()` |
| `syck_validate.py` | Zero-dep secret validation against 15+ provider APIs |
| `syck_sdk.py` | Programmatic Python SDK with `ScanResult`/`Summary` types |
| `syck_rpc.py` | JSON-RPC 2.0 interface over stdin/stdout for IDE plugins |
| `syck_server.py` | Thin shim → `syck/server/` REST API |
| `syck_cache.py` | SHA256 keyed scan result cache (14-day TTL) |
| `syck_sarif.py` | SARIF upload to GitHub Code Scanning API |
| `syck_webhook.py` | Webhook sender (Slack, Discord, JSON) |
| `syck-jsrecon.py` | JS recon wrapper → syck-hunt with `--deep-js` |
| `tests/` | Pytest test suite (29 tests) |
| `realistic_leaks_*` | Benchmark datasets (v1–v7, ignore for development) |
| `recon/` | Past syck-hunt output — do not treat as source |
| `install.sh` | Installs shims to `~/bin`, creates default config |
| `dummy_secrets.env` | Test fixture with fake secrets |

## Architecture

```
User CLI
  │
  ├─ syck.py  ───→  syck.cli.main()              # Scanner CLI
  │                    │
  │                    ├─ config.py               # Load ~/.config/syck/config.json etc.
  │                    ├─ scanner.py              # Core: scan_file, scan_string, scan_paths
  │                    │    ├─ decoders.py         # Line-level base64/hex/unicode/url decode
  │                    │    ├─ decoder_pipeline.py # Recursive multi-layer decode (depth 4)
  │                    │    ├─ endpoints.py        # API/GraphQL/WebSocket URL extraction
  │                    │    ├─ js_reconstruct.py   # JS concat/join/template reconstruction
  │                    │    ├─ json_scanner.py     # JSON tree walker for secret-keys
  │                    │    ├─ entropy.py          # Shannon entropy + likely_secret heuristic
  │                    │    ├─ rules.py            # 250+ Rule definitions
  │                    │    ├─ finding.py          # Finding + Rule dataclasses
  │                    │    ├─ git_scanner.py      # Git commit history scanning
  │                    │    ├─ ignore.py           # .syckignore fingerprint support
  │                    │    └─ formatters.py       # text/json/sarif/markdown/csv/html
  │                    │
  │                    ├─ syck_cache.py            # Optional content-hash cache
  │                    ├─ syck_validate.py         # Optional live validation
  │                    ├─ syck_webhook.py          # Optional webhook dispatch
  │                    └─ syck_sarif.py            # Optional SARIF upload
  │
  ├─ syck-hunt.py ─→  syck.hunt.cli.main()        # Recon pipeline CLI
  │                    │
  │                    ├─ stages.py                # Pipeline: subfinder → httpx → katana → download
  │                    ├─ recon.py                 # GAU, deep JS, source map extraction
  │                    └─ utils.py                 # Rate limiting, tool checks, checkpoint
  │
  ├─ syck-server.py ─→ syck/server/               # REST API (POST /scan, GET /rules, GET /health)
  │
  └─ syck_rpc.py       # JSON-RPC 2.0 over stdin/stdout
```

### syck/ Package Module Map

| Module | Lines | Responsibility |
|---|---|---|
| `cli.py` | 439 | argparse, config loading, pipeline orchestration (scan → validate → webhook → SARIF) |
| `scanner.py` | 615 | `scan_file()`, `scan_string()`, `scan_paths()`, streaming for large files, ThreadPool/ProcessPool parallelism, gzip decompression, dedup, FP downgrade |
| `rules.py` | 727 | 250+ `Rule` dataclass instances across 50+ provider categories, `load_custom_rules()` |
| `formatters.py` | 319 | 6 output formats: text, json, SARIF 2.1.0, markdown, CSV, dark-themed HTML |
| `decoder_pipeline.py` | 172 | Recursive decode (depth 4) across base64/hex/unicode/url, gzip/zlib decompression |
| `decoders.py` | 144 | Line-level base64/hex/unicode-escape/url-encoded decode + rescan |
| `entropy.py` | 61 | Shannon entropy calculator, `likely_secret()` heuristic, exclusion/context regexes |
| `js_reconstruct.py` | 130 | JS string concat chains, array `.join("")`, template literal reconstruction |
| `json_scanner.py` | 77 | Parses JSON, walks tree, checks values under known secret-key names |
| `finding.py` | 25 | `Finding` (file, line, column, rule, severity, secret, context, entropy, context_before/after) and `Rule` (name, severity, pattern) dataclasses |
| `git_scanner.py` | 92 | Walks `git log --all`, extracts file content per commit, runs `scan_file()` on temp files |
| `endpoints.py` | 45 | Extracts `/api/...`, `/graphql`, WebSocket URLs, fetch() calls tagged as INFO |
| `ignore.py` | 33 | SHA256 fingerprinting of findings + `.syckignore` file support |
| `config.py` | 37 | Loads from `~/.config/syck/config.json`, `.syckrc`, `.syckrc.json`, CLI override |
| `utils.py` | 148 | Colors, ANSI codes, `is_text_file()`, `parse_size()`, `iter_files()`, TEXT_EXTENSIONS, SKIP_DIRS |

### syck/hunt/ Subpackage

| Module | Lines | Responsibility |
|---|---|---|
| `cli.py` | 572 | argparse (50+ flags), full pipeline orchestration with checkpoint resume |
| `stages.py` | 577 | `stage_subfinder()`, `stage_httpx()`, `stage_katana()`, `stage_download()`, `stage_syck()`, `filter_scope()`, `stage_probe()`, checkpoint support |
| `recon.py` | 568 | Source map finding/extraction, deep JS recon (variables, API routes, tokens, hidden subdomains), GAU/Wayback stage, stream-JS mode |
| `utils.py` | 175 | `RateLimiter`, `HostLimiter` (per-host semaphore), `check_tools()`, `run_cmd()`, `_safe_name()`, `BANNER`, checkpoint constants |

### syck/async_fetch/ Subpackage

| Module | Lines | Responsibility |
|---|---|---|
| `cache.py` | ~60 | `URLContentCache` — SQLite-backed URL cache with 24h TTL |
| `fetcher.py` | ~120 | `fetch_urls_async()` (aiohttp) with ThreadPool fallback, content-type filtering |

### syck/server/ Subpackage

| Module | Lines | Responsibility |
|---|---|---|
| `__init__.py` | 185 | `SyckHandler` (http.server), POST /scan, GET /scan/<id>, GET /rules, GET /health |
| `__main__.py` | ~10 | argparse for host/port, calls `serve()` |

## Key Data Types

```python
@dataclass
class Finding:
    file: str          # Path or "git:<commit>:<path>" or URL
    line: int
    column: int        # Match position (0 = unknown)
    rule: str          # Rule name (e.g. "github_personal_access_token")
    severity: str      # CRITICAL / HIGH / MEDIUM / LOW / INFO
    secret: str        # The matched secret value
    context: str       # Surrounding line content
    context_before: str
    context_after: str
    entropy: float

@dataclass
class Rule:
    name: str
    severity: str
    pattern: re.Pattern

@dataclass
class ValidationResult:
    rule: str
    secret: str
    valid: bool
    detail: str    # e.g. "login: octocat" or "HTTP 401"

@dataclass
class ScanResult:     # From syck_sdk.py
    findings: list
    summary: Summary
    duration: float
    files_scanned: int
```

## Detection Rules (250+)

Categories: Cloud (AWS, GCP, Azure), Source Control (GitHub, GitLab, Bitbucket), Messaging (Slack, Discord, Telegram, Twilio, SendGrid), Payments (Stripe, Square, PayPal), AI Providers (OpenAI, Anthropic, HuggingFace, Replicate, Cohere, Groq, Perplexity, xAI, DeepSeek, Fireworks, ElevenLabs, Cerebras, NVIDIA, Runway, MiniMax, Alibaba, Moonshot, Tencent), SaaS (Supabase, PlanetScale, Linear, ngrok, Cloudflare, Doppler, Grafana, Algolia, Vercel, DigitalOcean, New Relic, Notion, Datadog, Sentry, PagerDuty), Infra (Vault, Docker Hub, Kubernetes, Terraform, Pulumi), Crypto (RSA/DSA/EC/OpenSSH/PGP private keys), Databases (Postgres, MySQL, MongoDB, Redis), Generic (Bearer/Basic auth, JWT, key=value, dotenv), CI/CD (GitHub Actions, CircleCI, Jenkins, Travis CI), SPA Config (Next.js __NEXT_DATA__, window.__INITIAL_STATE__), Enterprise (Jira, Sentry, LaunchDarkly, Elastic Cloud, Intercom).

Severity order: `CRITICAL (0) < HIGH (1) < MEDIUM (2) < LOW (3) < INFO (4)`

## Scanner Pipeline (scan_file)

1. File size check — streaming mode for >1MB files
2. Gzip/zlib decompression (if `--decode-gzip`) → scan decompressed content, tag with `gzip_` prefix
3. Entropy eligibility check — skip minified JS/bundler chunks, check for secret-context keywords
4. Line-by-line scan:
   a. Regex rules — each rule's pattern matched against each line
   b. Entropy tokens — `_ENTROPY_TOKEN_RE` matches 32+ char tokens in secret-context lines
   c. Decoders — base64/hex/unicode/url decode + rescan (tagged with `base64_`, `hex_` prefixes)
5. JSON-aware scan (`.json` files) — walk parsed JSON tree, check value under known secret-key names
6. Endpoint extraction (if `--endpoints`) — API routes tagged as INFO
7. JS reconstruction (if `--js-reconstruct`) — concat chains, array joins, template literals
8. Recursive decode (if `--decode-unicode` or `--decode-gzip`) — multi-layer up to depth 4

### post-scan pipeline (cli.py main)

1. `_downgrade_fp_findings()` — downgrades severity for findings in test/mock/vendor dirs, placeholder patterns
2. `deduplicate_findings()` — merges identical (rule, secret) across files
3. `filter_ignored()` — removes .syckignore fingerprints
4. `validate_findings()` (if `--validate`) — pings provider APIs
5. `send_webhooks()` (if `--webhook-url`) — posts to Slack/Discord/JSON
6. Formatter → stdout or file
7. `upload_sarif()` (if `--upload-sarif`) — uploads to GitHub Code Scanning
8. Exit code: 0 = no findings, 1 = findings found (or `--fail-on` threshold), 2 = bad args

## Hunt Pipeline (syck-hunt)

```
domains → [subfinder] → [httpx] → [katana/gau] → [scope filter] → [probe] → [download] → [syck scan]
```

Stages (numbered output files):
- `00_targets.txt` — input domains
- `01_subdomains.txt` — subfinder output (if `-es`)
- `02_live_hosts.txt` / `02_live_urls.txt` — httpx probes
- `03_urls.txt` — katana crawl or `03_wayback_urls.txt` — gau output
- `03c_merged_urls.txt` — merged URLs after JS URL extraction
- `04_syck_report.text` — syck scan results
- `downloaded/` — fetched JS/HTML/JSON files
- `resume.json` — checkpoint state

Optional stages: `stage_extract_js_urls()` (regex JS URL discovery), `stage_probe()` (httpx -mc 200 filter), `stage_extract_source_maps()` (fetch inline/remote source maps), `stage_deep_js()` (variable/endpoint/route extraction), `stage_gau()` (Wayback Machine URLs), `_stream_js()` (memory-only fetch + pipe to syck).

## Commands

```bash
python3 syck.py .                          # Scan current dir
python3 syck.py . --severity CRITICAL      # Critical only
python3 syck.py . --format sarif -o r.sarif
python3 syck.py . --format html -o report.html
python3 syck.py . --git-history            # Scan all git commits
python3 syck.py . --validate               # Check if keys are live (zero-dep)
python3 syck.py . --endpoints              # Extract API/GraphQL/WebSocket URLs
python3 syck.py . --no-dedup               # Show all occurrences
python3 syck.py . --ignore-file .syckignore
python3 syck.py . --decode-hex             # Decode hex + rescan
python3 syck.py . --js-reconstruct         # Reconstruct JS string concat/join/literals
python3 syck.py . --decode-gzip            # Decompress gzip/zlib content + rescan
python3 syck.py . --decode-unicode         # Decode \\uXXXX escapes + rescan
python3 syck.py . --redact                 # Mask secrets in output
python3 syck.py . --exclude 'test|mock'    # Skip paths matching regex
python3 syck.py . --list-rules             # List all rules and exit
python3 syck.py https://example.com/bundle.js    # Scan remote URL
python3 syck.py . --pipe < content.txt     # Scan from stdin
python3 syck.py . --fail-on HIGH           # CI gate — exit 1 if findings ≥ HIGH
python3 syck.py . --upload-sarif           # Upload SARIF to GitHub Code Scanning
python3 syck.py . --webhook-url https://... --webhook-format slack  # Post to Slack

cat .env | python3 syck.py . --pipe        # Pipe stdin

python3 syck-hunt example.com              # Full recon → scan
python3 syck-hunt example.com -ct          # Check tool deps
python3 syck-hunt -so ./repo -s CRITICAL   # Scan-only, no recon
python3 syck-hunt example.com -es          # With subdomain enumeration
python3 syck-hunt example.com --wayback    # Use Wayback URLs instead of katana
python3 syck-hunt example.com --scope 'example\.com'  # Filter URLs by scope regex
python3 syck-hunt example.com --resume     # Resume from last checkpoint
python3 syck-hunt example.com -nk          # Probe + download, no crawl
python3 syck-hunt example.com -hl          # Headless katana for SPA routes
python3 syck-hunt example.com -jsd 2       # Recursively follow JS imports
python3 syck-hunt example.com -sm          # Extract source maps + scan sources
python3 syck-hunt example.com -xs          # Extract inline <script> blocks
python3 syck-hunt example.com -ad          # Async download (aiohttp + SQLite cache)
python3 syck-hunt example.com --extract-js-urls   # JS URL discovery from crawled content
python3 syck-hunt example.com --stream-js         # In-memory fetch + pipe to syck
python3 syck-hunt example.com --deep-js           # Deep JS recon report

echo '{"method":"scan","params":{"paths":["."]},"id":1}' | python3 syck_rpc.py

python3 -m syck.server                    # Start REST API on :8080

python3 -m syck                           # Same as syck.py
```

## Critical Gotchas

- **Secrets print IN FULL by default.** Use `--redact` before sharing any output.
- **Exit code 1 = secrets found** (intentional, useful for CI gates). Exit code 2 = bad args.
- **`syck-hunt` auto-discovers `syck.py`** in same directory. Keep scripts together, or use `--syck-path`.
- **`recon/`** contains past scan output — do not treat as source code.
- **Go-based tools** (`httpx`, `subfinder`, `katana`) are from ProjectDiscovery, not Python equivalents.
- **Zero pip dependencies.** All HTTP uses stdlib `urllib.request`. Optional: `tqdm` (progress bar), `aiohttp` (async fetch).
- **`instructions.md` phase plan is fully implemented.** Phase 1-4 complete: package refactor, benchmarks, validation, enhanced detection.
- **New features must be opt-in via CLI flags.** Default behavior stays identical.
- **`Finding` dataclass fields must not be removed.** Adding new fields requires a default value.
- **All formatters handle all severity levels** including INFO.

## Style

- Python 3.10+ only (`X | Y` union types, `match` not used)
- No external type checkers — match existing type annotation style
- ANSI color codes hardcoded (no colorama)
- `Finding` dataclass is the core result type — never remove fields
- Zero pip dependencies. All HTTP calls use stdlib `urllib.request`.
- New features must be opt-in via CLI flags. Default behavior stays identical.
- syck-hunt pipeline preserves stage numbering (01_ through 04_). New stages use letters: `03b_`, `03c_`.

## Config

Config loaded from (first found wins, later files override earlier):
1. `~/.config/syck/config.json`
2. `~/.syckrc`
3. `.syckrc`
4. `.syckrc.json`
5. `--config FILE` (overrides all)

CLI flags override config values. Config keys normalize hyphens/spaces to underscores.

Example config (generated by install.sh):
```json
{
    "workers": 10,
    "max-file-size": "5M",
    "decode-base64": true,
    "decode-hex": true,
    "progress": true,
    "redact": false,
    "no-color": false
}
```

## Tests

```bash
python3 -m pytest tests/ -v              # Run all tests
python3 -m pytest tests/test_pipeline.py -v   # Decoder pipeline tests
python3 -m pytest tests/test_all_entrypoints.py -v  # Entry point tests
```

Test files: `test_all_entrypoints.py` (10), `test_decoders.py` (4), `test_column_context.py` (4), `test_js_reconstruct.py` (5), `test_pipeline.py` (6) = 29 tests total.
