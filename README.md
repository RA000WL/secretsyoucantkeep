# secretsyoucantkeep (`syck`)

> A local-first secrets scanner for bug bounty hunters — finds exposed
> credentials, API keys, tokens, and private keys in source code, JS
> bundles, repos, and recon output. Prints secrets **in full** so you
> can paste them straight into a report.

The repo is called `secretsyoucantkeep` (yes, with that name — the GitHub
repo URL is `github.com/RA000WL/secretsyoucantkeep`), but the scanner
binary is just `syck.py` and is invoked as `syck` for short.

Part of a two-script toolkit:

| Script | Short | Role |
|---|---|---|---|
| `syck.py`              | `syck` | The scanner — pattern-matches 179+ secret formats across files & dirs |
| `syck-hunt.py`         | `syck-hunt` | Recon pipeline — `domain → httpx → katana → syck` (subdomain enum is opt-in with `-es`) |
| `syck_sdk.py`          | `syck-sdk` | Python SDK — `scan()`, `scan_file()`, `scan_url()`, `validate()`, `list_rules()` |
| `syck_server.py`       | `syck-server` | REST API server — `POST /scan`, `GET /rules`, `GET /health` |
| `syck_rpc.py`          | `syck-rpc` | JSON-RPC 2.0 over stdin/stdout for IDE/editor extensions |
| `syck_webhook.py`      | — | Slack / Discord / JSON webhook dispatcher |
| `syck_sarif.py`        | — | GitHub Code Scanning SARIF upload |
| `syck_cache.py`        | — | SHA256 content caching module |
| `syck_async.py`        | — | Async URL fetcher via aiohttp (optional) |
| `syck_validate.py`     | `syck-validate` | Validate secrets against provider APIs |
| `syck-jsrecon.py`      | `syck-jsrecon` | Thin wrapper: `syck-hunt --deep-js` for JS recon |

---

## ⚠️ Safety first

`syck` prints **real secret values** to the terminal by default (so you can
copy them into your bounty report). The output is **not safe to share**.

- **Never** paste unredacted output into a public GitHub issue, Discord,
  HackerOne report preview, or any chat where unauthorised people can see.
- Use `--redact` to mask values, or send output to a private file:
  `syck . --redact --format html -o report.html`.
- Treat anything the scanner finds as **already leaked** — rotate it.

### Rate limiting

`syck-hunt` defaults to **50 requests/second** across all stages, with a
cap of **5 simultaneous requests per host**. This is fast enough for
authorised bug-bounty work on a single target. **If you don't have
written permission, lower the limit.**

```bash
syck-hunt example.com -rl 5           # 5 req/s (gentle, default was this in older versions)
syck-hunt example.com -rl 2           # 2 req/s (very gentle, WAF-aware)
syck-hunt example.com -rl 0           # disable all throttling (pentest only)
syck-hunt example.com -mc 1           # strictest: one request per host at a time
syck-hunt example.com -kc 5           # cap katana's own parallelism
```

The limiters affect:
- **`httpx`** — gets `-rate-limit <ms>` (the per-request delay in ms)
- **`katana`** — gets `-rate-limit <s>` + `-concurrency`
- **The downloader** — uses an internal token-bucket limiter + per-host
  semaphore, both configurable

If a program is run without explicit authorisation against the target, you
are responsible for staying within its acceptable rate. Drop the limit
when in doubt.

---

## Quick start

```bash
# 1. Scan a local repo / folder
python syck.py /path/to/repo

# 2. Full recon → secrets pipeline
python syck-hunt.py example.com

# 3. Just the report, no recon
python syck-hunt.py --scan-only ./cloned-repo --severity CRITICAL
```

---

## The pipeline

```
                 ┌────────────┐    ┌────────┐    ┌────────┐    ┌──────────────┐    ┌────────┐
  domain(s) ───▶ │   httpx    │──▶ │ katana │──▶ │download│──▶ │    syck      │──▶ report
                 └────────────┘    └────────┘    └────────┘    └──────────────┘    └────────┘
                  live hosts       crawled      *.js (default)    secrets
                  (and title)      URLs

  + optionally:  subfinder (enumerates subdomains first; -es to enable)
```

The default flow is the **fast path**: resolve the target with httpx,
crawl with katana, download the JS, scan with syck. Subdomain
enumeration is opt-in via `-es` — for a single-target scan you don't
need it.

Each stage writes to `recon/<target>/<timestamp>/` so you can re-run any
stage manually or feed intermediate files into other tools.

---

## Features

### Scanner (`syck.py` / `syck`)

- **179 detection rules** across cloud, source control, messaging,
  payments, AI providers, SaaS, infra, crypto, and databases
- **Custom rules** — load your own patterns from a JSON file with `--rules`
  (or replace built-in rules entirely with `--rules-only`)
- **Base64 decode pipeline** — decode base64 strings and re-scan for
  hidden secrets with `--decode-base64`
- **JSON-aware scanning** — parses JSON files and flags secret values
  under known secret keys (automatic, no flag needed)
- **Exclude patterns from file** — maintain a `.syckignore`-style file
  with `--exclude-file`
- **High-entropy token sweep** — catches undocumented secret formats
- **Parallel file scanning** with `ThreadPoolExecutor` (configurable workers);
  automatic `ProcessPoolExecutor` on Linux for 100+ file batches
- **Streaming mode** — files > 1MB scanned in streaming fashion for 10-50x
  peak memory reduction (automatic, no flag needed)
- **6 output formats**: text, JSON, SARIF (GitHub Code Scanning), Markdown,
  CSV, and a self-contained HTML report
- **Smart file filtering** — skips binary, honours file-size limits
  (with `K`/`M`/`G` suffix syntax), respects `.gitignore`-style dirs
- **Cross-platform** — pure Python 3.10+ stdlib, runs on Windows / macOS / Linux
- **Zero dependencies** — no `pip install` needed for core functionality
- **Config file support** — set defaults via `~/.config/syck/config.json` or
  `./.syckrc` (project-level). No need to repeat flags every run.
- **Auto-discovered syck** — `syck-hunt` finds `syck.py` in the same
  directory; no PATH setup required when scripts are kept together
- **Real-time progress** — shows file count, findings count, and ETA as
  scan progresses (auto-enabled for 20+ files); install `tqdm` for rich
  progress bars with throughput and ETA
- **Content caching** — SHA256-based caching in `.syck-cache/` for ~11x
  faster re-scans; `--no-cache` to skip, `--cache-dir` for custom path
- **Async URL fetching** — downloads remote URLs concurrently with aiohttp
  (optional; degrades gracefully to threaded fallback)
- **CI gate** — `--fail-on SEVERITY` exits 1 if any finding at or above
  the given severity (CRITICAL > HIGH > MEDIUM > LOW)
- **Webhook output** — `--webhook-url URL --webhook-format slack|discord|json`
  sends findings to Slack, Discord, or a custom JSON endpoint
- **GitHub SARIF upload** — `--upload-sarif` uploads SARIF output to GitHub
  Code Scanning (requires `--github-repo` and `--github-token`)
- **Debug mode** — `--debug` enables verbose logging for troubleshooting
- **Column tracking** — every finding includes the exact column position where
  the secret was matched (visible in JSON/SARIF/CSV outputs, adds precision to
  SARIF GitHub annotations)
- **Multi-line context** — findings include 2 lines of context before and after
  the matched line for easier triage
- **Gzip/Zlib decompression** — `--decode-gzip` decompresses gzip/zlib-compressed
  files (JS bundles, cached HTTP responses) and scans the decompressed content
- **Unicode escape decoding** — `--decode-unicode` decodes `\\uXXXX` escape
  sequences and re-scans for secrets hidden behind obfuscation
- **JS string reconstruction** — `--js-reconstruct` detects secrets split across
  string concatenations (`"a"+"b"+"c"`), array joins (`["a","b"].join("")`), and
  template literals, then scans the reconstructed value
- **Recursive decoder pipeline** — automatically chains all decoders
  (base64 → hex → unicode → gzip) recursively up to 4 layers deep, catching
  multi-encoded secrets like `base64(gzip(hex(secret)))`

### Pipeline (`syck-hunt.py`)

- One-command recon: `syck-hunt example.com`
- Subdomain enumeration is opt-in: `syck-hunt example.com -es`
- Multi-target: `syck-hunt -l domains.txt`
- Short flags for everything: `-nk` (no katana), `-nd` (no download),
  `-rl` (rate limit), `-mc` (max concurrent), etc.
- Skip stages with `-nk`, `-nd`
- JS-only download (default) or all files (`-aj` / `--all-files`)
- **Recursive JS crawling** — follow `import()`/`require()` URLs up to
  N levels deep with `--js-depth N`
- **Deep JS recon** — `-dj` / `--deep-js` extracts endpoints, API routes,
  JS variables, hidden admin routes, AWS/Google/Firebase keys, S3 buckets,
  Slack/Discord webhooks, JWT tokens, private keys, internal IPs, GraphQL
  endpoints, source maps, email addresses, hidden subdomains, and more from
  every JS file. Generates `deep_js_report.json`.
- **Source map extraction** — extract and scan original sources from
  source maps with `--extract-source-maps` / `-sm`
- **Inline script extraction** — extract `<script>` blocks from HTML
  files and scan them with `--extract-scripts` / `-xs`
- **Custom HTTP headers** — pass cookies or auth headers to access
  gated JS endpoints with `--header` and `--cookie`
- **Retry with backoff** — transient download failures retry up to 2
  times with exponential backoff (transparent, no flag needed)
- Dry-run (`-dr`) and tool-check (`-ct`) modes
- Pass-through of every `syck` option (`-s`, `-f`, `-r`, `-w`)
- **Auto-discovers syck** — no need to set up PATH; finds `syck.py`
  alongside `syck-hunt.py` automatically
- **Custom HTTP headers** — reach auth-gated JS with `--header`/`--cookie`

---

## Installation

### Requirements

- **Python 3.10+** (3.11 / 3.12 / 3.13 all fine)
- **Optional** — `aiohttp` for ~5x faster URL scanning and `tqdm` for
  rich progress bars (install both: `pip install aiohttp tqdm`)
- For the full `syck-hunt` pipeline, install the ProjectDiscovery toolchain:

| Tool | Install |
|---|---|
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx     | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| katana    | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |

Or grab pre-built binaries from each tool's GitHub releases page.

### Setup

```bash
git clone https://github.com/RA000WL/secretsyoucantkeep.git
cd secretsyoucantkeep/Script
chmod +x syck.py syck-hunt.py   # Unix only
```

### One-line installer (recommended for Linux / macOS / WSL)

```bash
./install.sh             # installs to ~/bin and patches your shell rc files
./install.sh --uninstall # undoes the install
./install.sh --prefix /usr/local/bin   # system-wide install
```

The installer:
- Drops `syck` and `syck-hunt` shims into `~/bin/`
- Patches `~/.zshenv` and `~/.profile` so the tools are visible to
  **non-interactive** shells (the classic WSL/`.zshrc`-alias gotcha)
- Also patches `~/.zshrc` and `~/.bashrc` for interactive shells
- Is **idempotent** — safe to re-run; uses marker comments to skip work
  that's already done
- Handles CRLF line endings if the repo was cloned on Windows

### Shell aliases (alternative, no installer needed)

Add to `~/.zshrc` or `~/.bashrc` if you'd rather not run the installer:

```bash
alias syck='python /path/to/syck.py'
syck-hunt() { python /path/to/syck-hunt.py "$@"; }
```

> **Heads up:** aliases only work in *interactive* shells. If you want
> `syck` to be callable from `wsl -d kali -- bash -c "syck"` or from
> `syck-hunt`'s internal `subprocess.run`, use the installer — it puts
> real binaries on `$PATH` instead of aliases.

Reload with `source ~/.zshrc` (or `~/.bashrc`).

---

## Usage — `syck` (scanner)

### Basic

```bash
syck .                              # scan current dir, show secrets in full
syck /path/to/repo                  # scan a repo
syck file.env secrets.yaml          # scan specific files
syck https://example.com/app.bundle.js   # scan a remote JS file directly
syck ./repo https://cdn.x/lib.js   # mix local paths and URLs
```

> URLs are downloaded to a temp file in the system temp dir, scanned,
> then deleted on exit.  Bad URLs print a warning to stderr and are
> skipped — they don't abort the run.  Combine with any other flag
> (`--severity`, `--format`, `--redact`, …) just like local files.

### Filter & format

```bash
syck . --severity CRITICAL          # only critical findings
syck . --redact                     # mask secrets in output
syck . --format sarif -o r.sarif    # SARIF for GitHub code scanning
syck . --format html -o r.html      # self-contained HTML report
syck . --format json | jq '.[]'     # pipe JSON into other tools
```

### Performance

```bash
syck . --workers 16                 # 16 parallel scanner workers
syck . --max-file-size 50M          # scan big build artefacts
syck . --exclude "test|mock|spec"   # skip noisy paths
syck . --no-entropy                 # disable the high-entropy sweep
syck . --no-cache                   # skip content caching
syck . --cache-dir /tmp/syck-cache  # custom cache location
```

### Config file

Default flags can be stored in a JSON config file — no need to repeat
them on every invocation:

- **Project-level**: `./.syckrc` or `./.syckrc.json`
- **User-level**: `~/.config/syck/config.json` or `~/.syckrc`

```json
{
  "severity": "HIGH",
  "workers": 8,
  "format": "html",
  "decode-base64": true
}
```

CLI flags override config values. Use `--config /path/to/file.json` for
an explicit config path.

### Advanced scanning

```bash
syck . --decode-base64                    # decode base64 strings and re-scan
syck . --exclude-file .syckignore          # load skip patterns from a file
```

Deep JSON scanning is automatic — syck parses `.json` files and flags
string values under keys like `password`, `secret`, `token`, `api_key`,
even if the value doesn't match a specific regex pattern.

### Reducing high-entropy false positives

The high-entropy sweep only runs on lines that look like they could
carry a secret (keywords: `api`, `key`, `token`, `secret`, `password`,
`auth`, `credential`, `bearer`, `aws`, `gcp`, `azure`, `jwt`, `oauth`,
`ssh_key`, …). This keeps the signal-to-noise ratio high.

It is also **skipped entirely on minified/bundled JS** (detected by
file name suffix — `.min.js`, `.bundle.js` — or by the file having
very few long lines), because those files contain thousands of
long tokens that all look high-entropy but are just minified
identifiers and base64 data URIs.

If you want to scan minified JS anyway, use `--no-entropy` is **not**
what you want (that disables the sweep globally). Instead, just run
without the entropy filter — but expect noise. Or use
`--exclude '.*\.min\.js'` to scope it.

Source map files (`.map`) are also skipped by default — they are
mostly base64-encoded source code that the entropy sweep misclassifies.

### Full option list

```
syck -h    # or --help
```

---

## Usage — `syck-hunt` (pipeline)

### End-to-end (default: target-only, no subdomain enum)

```bash
syck-hunt example.com                 # httpx → katana → download → syck
syck-hunt example.com -es             # also enumerate subdomains first
syck-hunt -l domains.txt -o ./recon   # multi-target
syck-hunt example.com -f sarif        # SARIF output for GitHub Code Scanning
```

### Short flag reference

| Short | Long                  | What it does                                  | Default |
|-------|-----------------------|-----------------------------------------------|---------|
| `-d`  | `--depth`             | Katana crawl depth                           | `2`     |
| `-o`  | `--output-dir`        | Output root                                  | `./recon` |
| `-f`  | `--format`            | Report format                                | `text`  |
| `-s`  | `--severity`          | Min severity                                 | `LOW`   |
| `-r`  | `--redact`            | Mask secrets in output                       | off     |
| `-l`  | `--list`              | File of domains                              | —       |
| `-es` | `--enum-subs`         | Enable subfinder (opt-in)                    | **off** |
| `-nk` | `--no-katana`         | Skip katana crawl                            | off     |
| `-nd` | `--no-download`       | Skip JS download                             | off     |
| `-js` | `--js-only`           | Download .js only (default)                  | on      |
| `-aj` | `--all-files`         | Download all crawled URLs, not just .js      | off     |
| `-mf` | `--max-files`         | Max files to download                        | `200`   |
| `-dw` | `--download-workers`  | Concurrent download workers                  | `10`    |
| `-mfs`| `--max-file-size`     | Max file size per scan                       | `5M`    |
| `-rl` | `--rate-limit`        | Max requests/sec across all stages           | **`50`** |
| `-mc` | `--max-concurrent`    | Max simultaneous requests per host           | `5`     |
| `-kc` | `--katana-conc`       | Katana `-concurrency`                        | `20`    |
| `-so` | `--scan-only`         | Skip recon, run syck on a local PATH         | —       |
| `-w`  | `--workers`           | syck workers                                 | `4`     |
| `-sp` | `--syck-path`         | Path to syck.py (if not on $PATH)            | —       |
| `-sm` | `--extract-source-maps`| Extract sources from source maps and scan   | off     |
| `-dj` | `--deep-js`           | Deep JS recon (24 extractors, generates JSON)| off     |
| `-jsd`| `--js-depth`          | Recursively follow JS imports up to N depth  | `0`     |
| `-xs` | `--extract-scripts`   | Extract inline `<script>` blocks from HTML   | off     |
|       | `--header`            | Custom HTTP header (repeatable)              | —       |
|       | `--cookie`            | Cookie header value                          | —       |
| `-ct` | `--check-tools`       | Check deps and exit                          | —       |
| `-dr` | `--dry-run`           | Print commands without running them          | —       |
| `-nc` | `--no-color`          | Disable coloured output                      | off     |

### Partial / specialised

```bash
syck-hunt example.com -nk             # httpx only (no crawl, no scan)
syck-hunt example.com -nd             # recon only, no scan stage
syck-hunt example.com -nk -nd         # just probe the target
syck-hunt -so ./leaked-repo -s CRITICAL   # skip recon, scan a local path
syck-hunt example.com -dr             # show commands, run nothing
syck-hunt -ct                         # verify deps are installed
syck-hunt example.com -rl 5           # slow down to 5 req/s
syck-hunt example.com -rl 0           # unlimited (authorised pentest only)
syck-hunt example.com -aj             # download all crawled files, not just .js
syck-hunt example.com -jsd 2          # recursively follow JS imports 2 levels deep
syck-hunt example.com -sm             # extract source maps + scan original sources
syck-hunt example.com -sm -jsd 1      # combine both: deep crawl + source map scan
syck-hunt example.com -xs              # extract inline <script> from HTML
syck-hunt example.com --cookie "session=abc" --header 'Authorization: Bearer x'  # auth-gated JS
```

### Subdomain enumeration (opt-in)

By default `syck-hunt` scans only the domain you give it — no
subdomain enumeration. To also enumerate subdomains, add `-es`:

```bash
syck-hunt example.com -es                  # subfinder → httpx → katana → syck
syck-hunt example.com -es -rl 2            # + be gentle
syck-hunt -l domains.txt -es -o ./recon    # multi-target with subdomains
```

`-es` makes `subfinder` a hard dependency. Use `--check-tools -es`
to confirm it's installed.

### Output

```
recon/
└── example.com/
    ├── 00_targets.txt        ← your input domain(s), or subfinder output
    ├── 02_live_hosts.txt     ← httpx output (status + title)
    ├── 02_live_urls.txt      ← clean URL list (input to katana)
    ├── 03_urls.txt           ← katana crawl output
    ├── downloaded/           ← JS files pulled by the downloader
    └── 04_syck_report.text   ← the report (printed to terminal too)
```

> Re-running `syck-hunt` on the same target overwrites the contents
> of that target's folder.  If you want history, put `./recon` under
> git, or `cp -r recon/<target> <backup>` before re-running.

---

## Output formats

| Format | Use case | Notes |
|---|---|---|
| `text`     | Terminal reading (default) | Coloured, with secret values inline |
| `json`     | Piping into `jq` / scripts | Full secret values, parseable |
| `sarif`    | GitHub Code Scanning upload | Use `--redact` before uploading |
| `markdown` | Bug-bounty report drafting | Tables + warning callout |
| `csv`      | Spreadsheet / grep workflows | One row per finding |
| `html`     | Standalone reviewable report | Self-contained, dark theme |

```bash
# Example: extract only critical OpenAI keys as a one-liner
syck . --format json --severity CRITICAL \
  | jq -r '.[] | select(.rule | startswith("openai_")) | .secret'
```

---

## What it detects

| Category | Coverage |
|---|---|
| **Cloud**          | AWS (access key, secret, session), GCP (API key, OAuth, service account, Firebase), Azure (storage, SAS, client secret), DigitalOcean, Cloudflare, Vercel |
| **Source control** | GitHub (PAT, OAuth, App, Server, Refresh, Fine-grained), GitLab (PAT, pipeline trigger) |
| **Messaging**      | Slack (token, webhook), Discord (bot, webhook), Telegram, Twilio (SID, auth, API key), Mailgun, SendGrid, Mailchimp, Brevo |
| **Payments**       | Stripe (secret, public, restricted, webhook), Square (access, OAuth), PayPal |
| **AI providers**   | OpenAI, Anthropic, HuggingFace, Replicate, Cohere, Groq, Perplexity |
| **SaaS**           | Supabase, PlanetScale, Linear, ngrok, New Relic, Datadog, Sentry, Pulumi, Dynatrace, Okta, Dropbox, Asana |
| **Infra**          | HashiCorp Vault (service/batch/recovery), Docker Hub, Kubernetes Secrets, PyPI, RubyGems, Terraform Cloud, SSH/SMTP/FTP passwords |
| **Crypto**         | RSA, DSA, EC, OpenSSH, PGP private keys, X.509 certificates |
| **Databases**      | Postgres, MySQL, MongoDB, Redis connection strings |
| **Generic**        | Bearer / Basic auth headers, JWT, `key=value` secrets, dotenv-style |
| **Catch-all**      | High-entropy token sweep (catches unknown patterns) |

Full list: `syck --list-rules` (100+ rules).

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No secrets found (or `--list-rules` / `--check-tools`) |
| `1`  | One or more secrets were found — useful in CI gates |
| `2`  | Invalid arguments / missing paths |

CI gate examples:

```bash
syck . --severity CRITICAL || { echo "CRITICAL secrets found"; exit 1; }
syck . --fail-on HIGH                # exit 1 if any HIGH or CRITICAL finding
syck . --fail-on CRITICAL            # exit 1 only for CRITICAL findings
```

---

## Bug-bounty tips

- **Run on a fresh clone of the target's public repos** — `syck --scan-only ./repo --severity CRITICAL`
- **Crawl the live app** for client-side leaks — `syck-hunt target.com` (JS-only is the default)
- **Audit JS bundles** that the site ships — they often contain
  embedded API keys for analytics, payments, maps
- **Watch for rotation gaps** — even if a key was rotated, the historical
  commit may still be public on GitHub
- **Cross-check secrets** with [Hibp](https://haveibeenpwned.com) and the
  provider's key-status endpoint to prove impact
- **Never re-test leaked keys** against production — that's a wire-fraud
  risk, not a bounty. Report and stop.

---

## Extending — adding a new rule

### Option A: Custom rules file (no code change)

Create a JSON file and pass it with `--rules`:

```bash
syck . --rules my_rules.json
```

```json
[
  {
    "name": "my_provider_api_key",
    "severity": "CRITICAL",
    "pattern": "\\bmpk_[A-Za-z0-9]{32,}\\b"
  }
]
```

Use `--rules-only` to replace built-in rules entirely with your own.

### Option B: Edit the source

Open `syck.py`, find the `RULES` list, and append a `Rule`:

```python
Rule("my_provider_api_key",
     "CRITICAL",                                     # or HIGH / MEDIUM / LOW
     re.compile(r"\bmpk_[A-Za-z0-9]{32,}\b")),       # the pattern
```

Severity guide:

- **CRITICAL** — direct account/org compromise (cloud root keys, OAuth tokens, private keys)
- **HIGH**     — significant service abuse (most SaaS API tokens)
- **MEDIUM**   — limited-scope or read-only tokens (publishable keys, public tokens)
- **LOW**      — informational (public URLs, certificates)

Test with the dummy file (`dummy_secrets.env`) or `syck --list-rules`.

---

## Scripts in this repo

```
syck.py              # the scanner (syck)
syck-hunt.py         # the recon pipeline (syck-hunt) — includes --deep-js JS recon
syck-jsrecon.py      # thin wrapper: syck-hunt --deep-js
syck_cache.py        # SHA256 content caching engine
syck_async.py        # async URL fetcher (aiohttp optional)
syck_sdk.py          # Python SDK with scan/validate/list_rules APIs
syck_server.py       # REST API server (POST /scan, GET /rules, GET /health)
syck_rpc.py          # JSON-RPC 2.0 over stdin/stdout for IDE plugins
syck_webhook.py      # Slack/Discord/JSON webhook dispatcher
syck_sarif.py        # GitHub Code Scanning SARIF upload
syck_validate.py     # validate secrets against provider APIs
install.sh           # one-line installer (Linux / macOS / WSL)
.gitattributes       # forces LF line endings for shell scripts
dummy_secrets.env    # test fixture with 100+ dummy secrets
```

---

## License

MIT — do what you want, no warranty. Be a good citizen and don't use this
to attack systems you don't have permission to test.

---

## Credits

- Built for the bug-bounty community.
- Pipeline integrations inspired by [ProjectDiscovery](https://github.com/projectdiscovery)'s
  recon stack (subfinder, httpx, katana).
