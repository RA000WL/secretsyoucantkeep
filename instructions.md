# Syck — Optimization Instructions for Agent

## Context

You are being given two Python tools built for bug bounty hunting:

- `syck.py` — a local secrets scanner. Scans files and folders for exposed credentials, API keys, tokens, and sensitive data using regex patterns, Shannon entropy analysis, and base64 decoding.
- `syck-hunt.py` — a recon orchestrator. Runs a pipeline: `subfinder → httpx → katana → download JS files → syck`. Automates crawling a target website and scanning its source files.

Both files are provided alongside this document. Read them fully before making changes. Do not break existing functionality. All improvements below are additive.

---

## Architecture Summary

### syck.py — key components

| Component | Location | Purpose |
|---|---|---|
| `RULES` list | top of file | All regex detection rules, each a `Rule(name, severity, pattern)` |
| `scan_file()` | mid-file | Core per-file scanner — runs rules + entropy + base64 |
| `_scan_json_file()` | mid-file | JSON-aware scanning for `.json` files |
| `_decode_and_rescan()` | mid-file | Base64 decode pipeline |
| `scan_paths()` | mid-file | Multi-threaded entry point — collects files, fans out |
| `Finding` dataclass | top | Result object: file, line, rule, severity, secret, context, entropy |
| `FORMATTERS` dict | mid-file | Output formatters: text, json, sarif, markdown, csv, html |
| `main()` | bottom | CLI entry point |

### syck-hunt.py — pipeline stages

| Stage | Function | Tool used |
|---|---|---|
| 1 (optional) | `stage_subfinder()` | subfinder |
| 2 | `stage_httpx()` | httpx |
| 3 | `stage_katana()` | katana |
| 4 | `stage_download()` | urllib / threading |
| 5 | `stage_extract_source_maps()` | built-in |
| 6 | `stage_syck()` | calls syck.py |

---

## Improvement 1 — Secret validation (CRITICAL priority)

### What and why
syck.py finds potential secrets but never verifies if they actually work. A valid live key is a confirmed bug bounty finding. A dead key is noise. Add a `--validate` flag that, after scanning, pings each provider's API to confirm the key is active.

### Where to add it
Add a new file `syck_validate.py` (imported by syck.py) with one async function per provider. Wire it into `main()` behind a `--validate` flag.

### Implementation

```python
# syck_validate.py
import httpx
from dataclasses import dataclass

@dataclass
class ValidationResult:
    rule: str
    secret: str
    valid: bool
    detail: str   # e.g. "account: acme@corp.com" or "HTTP 401"

def validate_github_pat(secret: str) -> ValidationResult:
    try:
        r = httpx.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {secret}"},
            timeout=8,
        )
        if r.status_code == 200:
            login = r.json().get("login", "unknown")
            return ValidationResult("github_pat", secret, True, f"login: {login}")
        return ValidationResult("github_pat", secret, False, f"HTTP {r.status_code}")
    except Exception as e:
        return ValidationResult("github_pat", secret, False, str(e))

def validate_stripe_secret(secret: str) -> ValidationResult:
    try:
        r = httpx.get(
            "https://api.stripe.com/v1/account",
            auth=(secret, ""),
            timeout=8,
        )
        valid = r.status_code == 200
        detail = r.json().get("email", "") if valid else f"HTTP {r.status_code}"
        return ValidationResult("stripe_secret_key", secret, valid, detail)
    except Exception as e:
        return ValidationResult("stripe_secret_key", secret, False, str(e))

def validate_aws_key(access_key: str, secret_key: str) -> ValidationResult:
    # requires boto3: pip install boto3
    try:
        import boto3
        sts = boto3.client(
            "sts",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        identity = sts.get_caller_identity()
        return ValidationResult(
            "aws_access_key_id", access_key, True,
            f"account: {identity['Account']}, arn: {identity['Arn']}"
        )
    except Exception as e:
        return ValidationResult("aws_access_key_id", access_key, False, str(e))

def validate_slack_token(secret: str) -> ValidationResult:
    try:
        r = httpx.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {secret}"},
            timeout=8,
        )
        data = r.json()
        if data.get("ok"):
            return ValidationResult("slack_token", secret, True,
                                    f"team: {data.get('team')}, user: {data.get('user')}")
        return ValidationResult("slack_token", secret, False, data.get("error", ""))
    except Exception as e:
        return ValidationResult("slack_token", secret, False, str(e))

def validate_sendgrid(secret: str) -> ValidationResult:
    try:
        r = httpx.get(
            "https://api.sendgrid.com/v3/user/profile",
            headers={"Authorization": f"Bearer {secret}"},
            timeout=8,
        )
        valid = r.status_code == 200
        return ValidationResult("sendgrid_api_key", secret, valid, f"HTTP {r.status_code}")
    except Exception as e:
        return ValidationResult("sendgrid_api_key", secret, False, str(e))

def validate_anthropic_key(secret: str) -> ValidationResult:
    try:
        r = httpx.get(
            "https://api.anthropic.com/v1/models",
            headers={"x-api-key": secret, "anthropic-version": "2023-06-01"},
            timeout=8,
        )
        valid = r.status_code == 200
        return ValidationResult("anthropic_api_key", secret, valid, f"HTTP {r.status_code}")
    except Exception as e:
        return ValidationResult("anthropic_api_key", secret, False, str(e))

def validate_openai_key(secret: str) -> ValidationResult:
    try:
        r = httpx.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {secret}"},
            timeout=8,
        )
        valid = r.status_code == 200
        return ValidationResult("openai_api_key", secret, valid, f"HTTP {r.status_code}")
    except Exception as e:
        return ValidationResult("openai_api_key", secret, False, str(e))

# Dispatch map: rule name → validator function
VALIDATORS = {
    "github_pat":        lambda s: validate_github_pat(s),
    "github_server_token": lambda s: validate_github_pat(s),
    "stripe_secret_key": lambda s: validate_stripe_secret(s),
    "slack_token":       lambda s: validate_slack_token(s),
    "sendgrid_api_key":  lambda s: validate_sendgrid(s),
    "anthropic_api_key": lambda s: validate_anthropic_key(s),
    "openai_api_key":    lambda s: validate_openai_key(s),
    "openai_project_key": lambda s: validate_openai_key(s),
}

def validate_findings(findings: list, workers: int = 5) -> dict:
    """
    Run validators against findings that have a matching rule.
    Returns dict keyed by (rule, secret[:20]) → ValidationResult.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    tasks = {}
    seen = set()
    for f in findings:
        if f.rule not in VALIDATORS:
            continue
        key = (f.rule, f.secret[:40])
        if key in seen:
            continue
        seen.add(key)
        tasks[key] = f

    results = {}
    with ThreadPoolExecutor(max_workers=workers) as exe:
        futs = {
            exe.submit(VALIDATORS[f.rule], f.secret): key
            for key, f in tasks.items()
        }
        for fut in as_completed(futs):
            key = futs[fut]
            try:
                results[key] = fut.result()
            except Exception:
                pass
    return results
```

### Wire into syck.py main()

In `build_parser()`, add:
```python
p.add_argument("--validate", action="store_true",
               help="Verify found secrets against provider APIs (requires httpx)")
```

In `main()`, after `findings = scan_paths(...)`:
```python
if args.validate and findings:
    from syck_validate import validate_findings
    print(color("[*] validating secrets against provider APIs…", CYAN), file=sys.stderr)
    validation = validate_findings(findings)
    for (rule, secret_prefix), result in validation.items():
        icon = color("[LIVE]", RED + BOLD) if result.valid else color("[DEAD]", GREY)
        print(f"  {icon} {rule}: {result.detail}", file=sys.stderr)
```

---

## Improvement 2 — Wayback Machine / GAU integration (CRITICAL priority)

### What and why
Old JS bundles archived before a secret rotation are a top source of valid bug bounty findings. `gau` (GetAllURLs) fetches historical URLs from Wayback Machine, Common Crawl, and OTX. Add it as an optional stage in syck-hunt.py that runs before the download stage and appends URLs to the katana output file.

### Where to add it
Add `stage_gau()` in syck-hunt.py, called between `stage_katana()` and `stage_download()` when `--wayback` flag is passed.

### Implementation

```python
def stage_gau(domains: list[str], urls_file: Path, out_dir: Path,
              dry_run: bool = False) -> Path:
    """
    Fetch historical URLs via gau and append JS URLs to the existing
    katana output file so the download stage picks them all up.
    """
    gau_out = out_dir / "03b_wayback_urls.txt"
    if not shutil.which("gau"):
        print(color("[!] gau not found — skipping wayback stage", YELL))
        print(color("    install: go install github.com/lc/gau/v2/cmd/gau@latest", GREY))
        return urls_file

    for domain in domains:
        cmd = ["gau", "--subs", "--blacklist", "png,jpg,gif,woff,css",
               "--o", str(gau_out), domain]
        print(color(f"[*] gau: fetching historical URLs for {domain}", CYAN))
        if not dry_run:
            run_cmd(cmd)

    if dry_run or not gau_out.exists():
        return urls_file

    # Filter to JS/JSON/config URLs and append to katana output
    appended = 0
    with urls_file.open("a", encoding="utf-8") as dst:
        for line in gau_out.open(encoding="utf-8", errors="replace"):
            url = line.strip()
            if not url:
                continue
            lower = url.lower()
            if any(ext in lower for ext in (".js", ".json", ".env", ".config", ".ts")):
                dst.write(url + "\n")
                appended += 1

    print(color(f"[+] appended {appended} historical URL(s) from gau", GREEN))
    return urls_file
```

### Add CLI flag in build_parser()

```python
stages.add_argument("--wayback", action="store_true",
                    help="Fetch historical URLs via gau (Wayback Machine + Common Crawl)")
```

### Call it in main()

After `urls = stage_katana(...)` and before `stage_download(...)`:
```python
if args.wayback and urls:
    urls = stage_gau(domains, urls, out_dir, dry_run=args.dry_run)
```

---

## Improvement 3 — API endpoint extraction (HIGH priority)

### What and why
syck.py reads every JS file but discards the API routes embedded in them. Endpoints like `/api/v1/admin/users` or `/internal/reset-password` are separate bug bounty findings. Add a new rule category called `endpoint` and a dedicated extractor.

### Where to add it
Add a new function `extract_endpoints()` in syck.py, called from `scan_file()`. Store endpoint findings using the existing `Finding` dataclass with a new severity level `INFO`.

### Implementation

```python
# Add to syck.py — endpoint extraction patterns
ENDPOINT_PATTERNS = [
    re.compile(r"""['"]((?:/api|/v\d+|/internal|/admin|/dashboard|/graphql|/rest)(?:/[a-zA-Z0-9_\-{}:]+){1,6})['""]"""),
    re.compile(r"""['"](/[a-z0-9_\-]+/(?:user|account|admin|auth|login|token|password|key|secret|config|setting)[a-z0-9_/\-]*)['""]""", re.I),
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"](https?://[^'"]+)['""]"""),
    re.compile(r"""(?:url|endpoint|baseURL|apiURL)\s*[:=]\s*['"](https?://[^'"]{10,})['""]""", re.I),
    re.compile(r"""wss?://[a-zA-Z0-9\-._]+(?:/[a-zA-Z0-9_/\-]*)?"""),  # WebSocket URLs
]

GRAPHQL_PATTERN = re.compile(
    r"""['"]((?:https?://[^'"]+)?/graphql(?:/[a-zA-Z0-9_\-]*)?)['""]""", re.I
)

def extract_endpoints(path: Path, content: str) -> list[Finding]:
    """Extract API endpoints and URLs from source files."""
    findings: list[Finding] = []
    seen: set[str] = set()

    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for pattern in ENDPOINT_PATTERNS + [GRAPHQL_PATTERN]:
            for m in pattern.finditer(line):
                endpoint = m.group(1)
                if endpoint in seen or len(endpoint) < 5:
                    continue
                # Skip obvious static assets
                if any(endpoint.endswith(ext) for ext in
                       (".png", ".jpg", ".gif", ".css", ".ico", ".woff", ".svg")):
                    continue
                seen.add(endpoint)
                findings.append(Finding(
                    file=str(path),
                    line=lineno,
                    rule="endpoint",
                    severity="INFO",
                    secret=endpoint,
                    context=line.strip()[:200],
                    entropy=0.0,
                ))
    return findings
```

Add `INFO` to `SEVERITY_ORDER`:
```python
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
```

Call from `scan_file()`:
```python
if getattr(args_local, "extract_endpoints", False):
    findings.extend(extract_endpoints(path, content))
```

Add CLI flag:
```python
p.add_argument("--endpoints", action="store_true",
               help="Also extract API endpoints and URLs from source files")
```

---

## Improvement 4 — Missing detection rules (HIGH priority)

### What and why
Several commonly found tokens in bug bounty programs are not covered by RULES. Add all of the following to the `RULES` list in syck.py.

### Implementation — append to RULES list

```python
# ── Atlassian / Jira ──────────────────────────
Rule("jira_atlassian_token",
     "CRITICAL",
     re.compile(r"\bATATT3xFfGF0[A-Za-z0-9_\-]{40,}\b")),

# ── Postman ───────────────────────────────────
Rule("postman_api_key",
     "CRITICAL",
     re.compile(r"\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b")),

# ── Airtable ──────────────────────────────────
Rule("airtable_api_key",
     "HIGH",
     re.compile(r"\bkey[A-Za-z0-9]{14}\b")),

# ── LaunchDarkly ──────────────────────────────
Rule("launchdarkly_sdk_key",
     "HIGH",
     re.compile(r"\bsdk-[A-Za-z0-9_\-]{40,}\b")),

Rule("launchdarkly_mobile_key",
     "HIGH",
     re.compile(r"\bmob-[A-Za-z0-9_\-]{40,}\b")),

# ── Sentry auth token (different from DSN) ────
Rule("sentry_auth_token",
     "CRITICAL",
     re.compile(r"\b[a-f0-9]{64}\b")),  # 64-char hex — filter by context

# ── Intercom ──────────────────────────────────
Rule("intercom_access_token",
     "HIGH",
     re.compile(r"\bdG9rO[A-Za-z0-9+/=]{30,}\b")),

# ── Mixpanel ──────────────────────────────────
Rule("mixpanel_token",
     "MEDIUM",
     re.compile(r"(?i)mixpanel[_\-]?(?:token|secret)\s*[:=]\s*['\"]?[A-Za-z0-9]{32}['\"]?")),

# ── Segment ───────────────────────────────────
Rule("segment_write_key",
     "HIGH",
     re.compile(r"(?i)segment[_\-]?(?:write[_\-]?)?key\s*[:=]\s*['\"]?[A-Za-z0-9]{40,}['\"]?")),

# ── Elastic Cloud ─────────────────────────────
Rule("elastic_cloud_api_key",
     "CRITICAL",
     re.compile(r"\bApiKey\s+[A-Za-z0-9+/=]{40,}\b")),

# ── Next.js / SPA embedded config ─────────────
Rule("nextjs_data_block",
     "MEDIUM",
     re.compile(r'<script id="__NEXT_DATA__"[^>]*>(\{.{20,}?\})</script>', re.DOTALL)),

Rule("window_initial_state",
     "MEDIUM",
     re.compile(r'window\.__(?:INITIAL_STATE|APP_STATE|CONFIG|ENV)__\s*=\s*(\{.+?\});', re.DOTALL)),

# ── CI/CD secrets ─────────────────────────────
Rule("github_actions_secret_ref",
     "LOW",
     re.compile(r'\$\{\{\s*secrets\.([A-Z_]{4,})\s*\}\}')),

Rule("ci_inline_env_secret",
     "HIGH",
     re.compile(r'(?im)^\s+[A-Z_]{3,}(?:KEY|TOKEN|SECRET|PASSWORD|PASS|PWD)\s*:\s*(?!"\$).{8,}')),

# ── Azure Active Directory ────────────────────
Rule("azure_ad_client_secret",
     "CRITICAL",
     re.compile(r"(?i)client[_\-]?secret\s*[:=]\s*['\"]?[A-Za-z0-9~._\-]{34,}['\"]?")),

# ── Cloudinary full URL ───────────────────────
Rule("cloudinary_full_url",
     "HIGH",
     re.compile(r"cloudinary://[A-Za-z0-9]+:[A-Za-z0-9]+@[a-z]+")),
```

---

## Improvement 5 — Secret deduplication across files (MEDIUM priority)

### What and why
Currently the same AWS key appearing in 50 files generates 50 findings. Add a deduplication pass that groups findings by unique secret value and consolidates them into a single finding with a `files` list.

### Where to add it
Add a `deduplicate_findings()` function and call it in `main()` after `scan_paths()`.

### Implementation

```python
def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Merge findings with identical (rule, secret) into one finding.
    The merged finding keeps the first occurrence's file/line but
    adds an 'also_in' count to the context.
    """
    seen: dict[tuple, Finding] = {}
    counts: dict[tuple, int] = {}

    for f in findings:
        key = (f.rule, f.secret)
        if key not in seen:
            seen[key] = f
            counts[key] = 1
        else:
            counts[key] += 1

    result = []
    for key, f in seen.items():
        n = counts[key]
        if n > 1:
            import dataclasses
            f = dataclasses.replace(
                f,
                context=f"{f.context}  [also found in {n - 1} other file(s)]"
            )
        result.append(f)

    result.sort(key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.file, x.line))
    return result
```

In `main()`:
```python
findings = scan_paths(...)
if not args.no_dedup:
    findings = deduplicate_findings(findings)
```

Add CLI flag:
```python
p.add_argument("--no-dedup", action="store_true",
               help="Show all findings including duplicates across files")
```

---

## Improvement 6 — .syckignore allowlist (MEDIUM priority)

### What and why
Re-running on the same target always reports the same false positives with no way to suppress them. Add a `.syckignore` file that fingerprints known-false-positive findings so they are excluded from future runs.

### Implementation

```python
import hashlib

def _finding_fingerprint(f: Finding) -> str:
    """Stable SHA256 fingerprint for a finding."""
    raw = f"{f.rule}:{f.secret[:60]}:{Path(f.file).name}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def load_ignore_list(path: Path | None = None) -> set[str]:
    """Load fingerprints from .syckignore in cwd or explicit path."""
    candidates = [Path(".syckignore")]
    if path:
        candidates.insert(0, path)
    for p in candidates:
        if p.exists():
            lines = p.read_text(encoding="utf-8").splitlines()
            return {
                line.split("#")[0].strip()
                for line in lines
                if line.strip() and not line.startswith("#")
            }
    return set()


def filter_ignored(findings: list[Finding],
                   ignore: set[str]) -> list[Finding]:
    if not ignore:
        return findings
    return [f for f in findings if _finding_fingerprint(f) not in ignore]
```

In `main()`:
```python
ignore = load_ignore_list(Path(args.ignore_file) if args.ignore_file else None)
findings = filter_ignored(findings, ignore)
```

Add CLI flags:
```python
p.add_argument("--ignore-file", metavar="FILE",
               help="Path to ignore file (default: ./.syckignore)")
p.add_argument("--add-ignore", metavar="FINGERPRINT",
               help="Add a finding fingerprint to .syckignore and exit")
```

Format: `.syckignore` is a plain text file, one fingerprint per line, `#` comments supported:
```
# known false positives
a1b2c3d4e5f6g7h8  # test key in mock data
b9c8d7e6f5g4h3i2  # placeholder in README
```

---

## Improvement 7 — Scope filtering in syck-hunt.py (MEDIUM priority)

### What and why
subfinder can find hundreds of subdomains but a bug bounty program may only allow `*.example.com` and `app.example.com`. Scanning out-of-scope hosts can get you banned from a program.

### Where to add it
In `stage_httpx()`, filter the subs file before passing to httpx. Also add scope check in `stage_download()`.

### Implementation

```python
def filter_scope(hosts_file: Path, scope_regex: str,
                 out_dir: Path) -> Path:
    """Filter a host/URL list to only in-scope entries."""
    try:
        pattern = re.compile(scope_regex, re.I)
    except re.error as e:
        print(color(f"[!] invalid scope regex: {e}", RED), file=sys.stderr)
        return hosts_file

    scoped = out_dir / "scoped_hosts.txt"
    kept = 0
    skipped = 0
    with scoped.open("w", encoding="utf-8") as dst:
        for line in hosts_file.open(encoding="utf-8", errors="replace"):
            host = line.strip()
            if not host:
                continue
            if pattern.search(host):
                dst.write(host + "\n")
                kept += 1
            else:
                skipped += 1

    print(color(f"[+] scope filter: {kept} in-scope, {skipped} excluded", GREEN))
    return scoped
```

Add CLI flag:
```python
stages.add_argument("--scope", metavar="REGEX",
                    help="Only scan hosts matching this regex "
                         "(e.g. --scope r'^.*\\.example\\.com$')")
```

Call in `main()` after `stage_subfinder()` / after writing `00_targets.txt`:
```python
if args.scope and subs:
    subs = filter_scope(subs, args.scope, out_dir)
```

---

## Improvement 8 — Resume / checkpoint support in syck-hunt.py (MEDIUM priority)

### What and why
If the katana stage crashes on a long scan, the entire run restarts from scratch. Add a checkpoint system so completed stages are skipped on rerun.

### Implementation

```python
_CHECKPOINT_FILE = ".syck_checkpoint.json"

def _load_checkpoints(out_dir: Path) -> dict:
    cp = out_dir / _CHECKPOINT_FILE
    if cp.exists():
        try:
            return json.loads(cp.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def _save_checkpoint(out_dir: Path, stage: str, output_path: str) -> None:
    cp = out_dir / _CHECKPOINT_FILE
    data = _load_checkpoints(out_dir)
    data[stage] = {"done": True, "output": output_path,
                   "time": datetime.now().isoformat()}
    cp.write_text(json.dumps(data, indent=2), encoding="utf-8")

def _checkpoint_done(out_dir: Path, stage: str) -> str | None:
    """Returns output path if stage already completed, else None."""
    data = _load_checkpoints(out_dir)
    entry = data.get(stage)
    if entry and entry.get("done") and Path(entry["output"]).exists():
        return entry["output"]
    return None
```

Use in each stage in `main()`:
```python
# Example for katana stage
if not args.resume or not (prev := _checkpoint_done(out_dir, "katana")):
    urls = stage_katana(hosts, out_dir, ...)
    if urls:
        _save_checkpoint(out_dir, "katana", str(urls))
else:
    urls = Path(prev)
    print(color(f"[*] resuming: skipping katana (already done → {urls})", CYAN))
```

Add CLI flag:
```python
misc.add_argument("--resume", action="store_true",
                  help="Skip already-completed stages (uses .syck_checkpoint.json)")
```

---

## Improvement 9 — Git history scanning (CRITICAL priority)

### What and why
Most accidentally committed secrets are in deleted commits — developers commit a `.env` file, panic, delete it in the next commit, but the secret stays in git history forever. Neither tool scans git history at all.

### Where to add it
Add a `scan_git_history()` function in syck.py, exposed via `--git-history` flag.

### Implementation

```python
import subprocess
import tempfile

def scan_git_history(repo_path: Path, min_severity: str = "LOW",
                     workers: int = 4) -> list[Finding]:
    """
    Walk all commits in the git repo at repo_path, extract file contents
    from each commit, and run syck rules against them.
    Only scans commits that touched files matching TEXT_EXTENSIONS.
    """
    findings: list[Finding] = []

    # Get all commit hashes
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "log",
             "--all", "--format=%H", "--diff-filter=AM"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(color(f"[!] git log failed: {result.stderr[:200]}", YELLOW),
                  file=sys.stderr)
            return findings
        commits = [h.strip() for h in result.stdout.splitlines() if h.strip()]
    except Exception as e:
        print(color(f"[!] git history scan error: {e}", YELLOW), file=sys.stderr)
        return findings

    print(color(f"[*] scanning git history: {len(commits)} commit(s)…", GREY),
          file=sys.stderr)

    seen_secrets: set[tuple] = set()

    for commit in commits:
        # List files changed in this commit
        try:
            ls = subprocess.run(
                ["git", "-C", str(repo_path), "diff-tree",
                 "--no-commit-id", "-r", "--name-only", commit],
                capture_output=True, text=True, timeout=30
            )
            files_in_commit = [f.strip() for f in ls.stdout.splitlines() if f.strip()]
        except Exception:
            continue

        for filepath in files_in_commit:
            suffix = Path(filepath).suffix.lower()
            if suffix not in TEXT_EXTENSIONS:
                continue
            try:
                cat = subprocess.run(
                    ["git", "-C", str(repo_path), "show", f"{commit}:{filepath}"],
                    capture_output=True, text=True, timeout=15, errors="replace"
                )
                if cat.returncode != 0:
                    continue
                content = cat.stdout
            except Exception:
                continue

            # Write to temp file and scan
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=Path(filepath).suffix,
                delete=False, encoding="utf-8"
            ) as tmp:
                tmp.write(content)
                tmp_path = Path(tmp.name)

            try:
                file_findings = scan_file(tmp_path, min_severity)
            finally:
                tmp_path.unlink(missing_ok=True)

            for f in file_findings:
                dedup_key = (f.rule, f.secret[:40])
                if dedup_key not in seen_secrets:
                    seen_secrets.add(dedup_key)
                    findings.append(Finding(
                        file=f"git:{commit[:8]}:{filepath}",
                        line=f.line,
                        rule=f.rule,
                        severity=f.severity,
                        secret=f.secret,
                        context=f.context,
                        entropy=f.entropy,
                    ))

    return findings
```

Add CLI flag in `build_parser()`:
```python
p.add_argument("--git-history", action="store_true",
               help="Also scan git commit history for secrets in deleted files "
                    "(requires git in PATH, run from inside a repo)")
```

In `main()`, after `scan_paths()`:
```python
if args.git_history:
    for target in targets:
        if (target / ".git").exists() or target.name == ".git":
            repo = target if (target / ".git").exists() else target.parent
            print(color(f"[*] scanning git history of {repo}…", GREY), file=sys.stderr)
            findings.extend(scan_git_history(repo, args.severity, args.workers))
```

---

## Testing the improvements

After implementing, test each feature:

```bash
# Test secret validation
python3 syck.py ./test_keys --validate

# Test wayback integration (requires gau installed)
python3 syck-hunt.py testphp.vulnweb.com --wayback --dry-run

# Test endpoint extraction
python3 syck.py ./juice-shop/frontend/dist --endpoints --format json

# Test git history scanning (run inside a repo)
python3 syck.py . --git-history --severity HIGH

# Test deduplication
python3 syck.py ./test_keys --no-dedup  # should show more findings
python3 syck.py ./test_keys             # should deduplicate

# Test scope filtering
python3 syck-hunt.py example.com --scope "^.*\.example\.com$" --dry-run

# Test resume
python3 syck-hunt.py target.com --resume  # second run should skip completed stages
```

Use `https://github.com/trufflesecurity/test_keys` as test data — it contains real-format fake keys specifically designed for testing secret scanners.

---

## Constraints — do not break these

- All new features must be opt-in via CLI flags. Default behavior must stay identical.
- `Finding` dataclass fields must not be removed. Adding new fields requires a default value.
- All output formatters (text, json, sarif, markdown, csv, html) must handle the new `INFO` severity level.
- The `--redact` flag must apply to all new findings.
- syck-hunt.py's existing stage numbering (01_ through 04_) should be preserved. New stages use letters: `03b_`, `05b_` etc.
- Python 3.10+ only. No new mandatory dependencies — optional deps (boto3, httpx) should be caught with a clear `pip install` hint if missing.
