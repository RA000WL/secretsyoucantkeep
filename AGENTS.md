# AGENTS.md

## What this repo is

Two Python scripts for bug bounty secret scanning — no package manager, no tests, no CI, no dependencies beyond Python 3.10+ stdlib.

| File | Purpose |
|---|---|
| `syck.py` | Scanner — regex + entropy + base64 decode pipeline, 110+ rules |
| `syck-hunt.py` | Recon pipeline — `httpx → katana → download JS → syck` |
| `syck_validate.py` | Secret validation — pings provider APIs to confirm live keys (zero deps) |
| `install.sh` | Installs shims to `~/bin`, patches shell rc files |
| `instructions.md` | Planned improvements (FULLY implemented) |
| `dummy_secrets.env` | Test fixture with fake secrets — safe to scan |

## Commands

```bash
python3 syck.py .                          # scan current dir
python3 syck.py dummy_secrets.env          # test against fixture
python3 syck.py . --severity CRITICAL      # critical only
python3 syck.py . --format sarif -o r.sarif
python3 syck.py . --git-history            # scan all commits for deleted secrets
python3 syck.py . --validate               # check if found keys are actually live
python3 syck.py . --endpoints              # extract API/GraphQL/WebSocket URLs
python3 syck.py . --no-dedup               # show all occurrences (default: dedup ON)
python3 syck.py . --ignore-file .syckignore # suppress known false positives
python3 syck.py . --decode-hex             # decode hex-encoded strings and rescan
python3 syck-hunt example.com              # full recon → scan
python3 syck-hunt example.com -ct          # check tool deps
python3 syck-hunt -so ./repo -s CRITICAL   # scan-only, no recon
python3 syck-hunt example.com --wayback    # use Wayback URLs instead of katana
python3 syck-hunt example.com --scope 'example\.com'  # filter URLs by scope
python3 syck-hunt example.com --resume     # resume from last checkpoint
```

No lint/typecheck/test commands exist. There is no test suite.

## Critical gotchas

- **`instructions.md` is partially implemented.** Phase 1-4 features are now in `syck.py`: dedup, .syckignore, endpoint extraction, missing rules, INFO severity, git history scanning, secret validation, hex decoding, Wayback/scope/resume in `syck-hunt.py`.
- **Secrets print IN FULL by default.** Use `--redact` before sharing any output.
- **Exit code 1 = secrets found** (intentional, useful for CI gates). Exit code 2 = bad args.
- **`syck-hunt` auto-discovers `syck.py`** in the same directory. If you move scripts, keep them together.
- **`recon/`** contains past scan output — do not treat as source code.
- **Go-based `httpx` (ProjectDiscovery)** is the recon tool used by `syck-hunt.py`. Not to be confused with the Python `httpx` library — we do NOT use Python httpx here.

## Architecture

Single-file scripts, no internal package structure. Key entry points:

- `syck.py:main()` → `scan_paths()` → `scan_file()` per file
- `syck.py:RULES` list (top) — all 110+ detection patterns
- `syck.py:FORMATTERS` dict — text/json/sarif/markdown/csv/html
- `syck.py:deduplicate_findings()` — merges identical secrets across files
- `syck.py:scan_git_history()` — walks all git commits, extracts deleted files
- `syck.py:extract_endpoints()` — API route / GraphQL / WebSocket extraction
- `syck_validate.py:VALIDATORS` — dispatch map of provider API checkers
- `syck-hunt.py:main()` → sequential stages (subfinder → httpx → katana → download → syck)
- `syck-hunt.py:stage_syck()` invokes `syck.py` as a subprocess
- `syck-hunt.py:stage_gau()` — Wayback Machine URL discovery via gau/waybackurls
- `syck-hunt.py:filter_scope()` — regex URL filtering
- `syck-hunt.py:save/load_checkpoint()` — resume support

## Style

- Python 3.10+ only (`X | Y` union types, `match` not used)
- No type annotations beyond what's already there — match existing style
- ANSI color codes hardcoded at top of each file (no colorama)
- `Finding` dataclass is the core result type — never remove fields
- Zero pip dependencies. All HTTP calls use stdlib `urllib.request`.
- New features must be opt-in via CLI flags. Default behavior stays identical.
