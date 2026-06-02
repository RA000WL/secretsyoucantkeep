# secretsyoucantkeep (`syck`)

> A local-first secrets scanner for bug bounty hunters — finds exposed
> credentials, API keys, tokens, and private keys in source code, JS
> bundles, repos, and recon output. Prints secrets **in full** so you
> can paste them straight into a report.

Part of a two-script toolkit:

| Script | Short | Role |
|---|---|---|
| `secretsyoucantkeep.py` | `syck` | The scanner — pattern-matches 100+ secret formats across files & dirs |
| `syck-hunt.py`         | `syck-hunt` | Recon pipeline — wires `subfinder → httpx → katana → syck` into one command |

---

## ⚠️ Safety first

`syck` prints **real secret values** to the terminal by default (so you can
copy them into your bounty report). The output is **not safe to share**.

- **Never** paste unredacted output into a public GitHub issue, Discord,
  HackerOne report preview, or any chat where unauthorised people can see.
- Use `--redact` to mask values, or send output to a private file:
  `syck . --redact --format html -o report.html`.
- Treat anything the scanner finds as **already leaked** — rotate it.

---

## Quick start

```bash
# 1. Scan a local repo / folder
python secretsyoucantkeep.py /path/to/repo

# 2. Full recon → secrets pipeline
python syck-hunt.py example.com

# 3. Just the report, no recon
python syck-hunt.py --scan-only ./cloned-repo --severity CRITICAL
```

---

## The pipeline

```
                 ┌────────────┐    ┌────────┐    ┌────────┐    ┌──────────────┐    ┌────────┐
  domain(s) ───▶ │ subfinder  │──▶ │ httpx  │──▶ │ katana │──▶ │ download JS  │──▶ │  syck  │──▶ report
                 └────────────┘    └────────┘    └────────┘    └──────────────┘    └────────┘
                  subdomains       live hosts    crawled      *.js (default)      secrets
                                                   URLs
```

Each stage writes to `recon/<target>/<timestamp>/` so you can re-run any
stage manually or feed intermediate files into other tools.

---

## Features

### Scanner (`secretsyoucantkeep.py` / `syck`)

- **100+ detection rules** across cloud, source control, messaging,
  payments, AI providers, SaaS, infra, crypto, and databases
- **High-entropy token sweep** — catches undocumented secret formats
- **Parallel file scanning** with `ThreadPoolExecutor` (configurable workers)
- **6 output formats**: text, JSON, SARIF (GitHub Code Scanning), Markdown,
  CSV, and a self-contained HTML report
- **Smart file filtering** — skips binary, honours file-size limits
  (with `K`/`M`/`G` suffix syntax), respects `.gitignore`-style dirs
- **Cross-platform** — pure Python 3.10+ stdlib, runs on Windows / macOS / Linux
- **Zero dependencies** — no `pip install` needed

### Pipeline (`syck-hunt.py`)

- One-command recon: `syck-hunt example.com`
- Multi-target: `syck-hunt -l domains.txt`
- Skip stages with `--no-katana`, `--no-download`
- JS-only download (default) or all files (`--no-js-only`)
- Dry-run (`--dry-run`) and tool-check (`--check-tools`) modes
- Pass-through of every `syck` option (`--severity`, `--format`, `--redact`)

---

## Installation

### Requirements

- **Python 3.10+** (3.11 / 3.12 / 3.13 all fine)
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
chmod +x secretsyoucantkeep.py syck-hunt.py   # Unix only
```

### Shell aliases (optional)

Add to `~/.zshrc` or `~/.bashrc`:

```bash
alias syck='python /path/to/secretsyoucantkeep.py'
syck-hunt() { python /path/to/syck-hunt.py "$@"; }
```

Reload with `source ~/.zshrc` (or `~/.bashrc`).

---

## Usage — `syck` (scanner)

### Basic

```bash
syck .                              # scan current dir, show secrets in full
syck /path/to/repo                  # scan a repo
syck file.env secrets.yaml          # scan specific files
```

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
```

### Full option list

```
syck -h    # or --help
```

---

## Usage — `syck-hunt` (pipeline)

### End-to-end

```bash
syck-hunt example.com
syck-hunt example.com --js-only
syck-hunt -l domains.txt --output-dir ./recon
```

### Partial / specialised

```bash
syck-hunt example.com --no-katana            # subfinder + httpx only
syck-hunt example.com --no-download          # recon only, no scan
syck-hunt --scan-only ./leaked-repo          # skip recon, scan a local path
syck-hunt example.com --dry-run              # show commands, run nothing
syck-hunt --check-tools                      # verify deps are installed
```

### Output

```
recon/
└── example.com/
    └── 20260602_223729/
        ├── 01_subdomains.txt
        ├── 02_live_hosts.txt
        ├── 02_live_urls.txt
        ├── 03_urls.txt
        ├── downloaded/        ← JS files pulled by the crawler
        └── 04_syck_report.html
```

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

CI gate example:

```bash
syck . --severity CRITICAL || { echo "CRITICAL secrets found"; exit 1; }
```

---

## Bug-bounty tips

- **Run on a fresh clone of the target's public repos** — `syck --scan-only ./repo --severity CRITICAL`
- **Crawl the live app** for client-side leaks — `syck-hunt target.com --js-only`
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

Open `secretsyoucantkeep.py`, find the `RULES` list, and append a `Rule`:

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
secretsyoucantkeep.py     # the scanner (syck)
syck-hunt.py              # the recon pipeline (syck-hunt)
dummy_secrets.env         # test fixture with 100+ dummy secrets
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
