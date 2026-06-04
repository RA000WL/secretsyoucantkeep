"""syck.hunt.recon — source-map extraction, deep JS recon, GAU + stream-JS stages."""
from __future__ import annotations

import base64
import concurrent.futures
import json
import re
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from syck.hunt.utils import (
    CYAN, GREEN, GREY, RED, YELL,
    HostLimiter, RateLimiter,
    _safe_name, color, run_cmd, which,
)

# ──────────────────────────────────────────────
# Source map / JS url extractors
# ──────────────────────────────────────────────

_SOURCEMAP_URL_RE = re.compile(r'//# sourceMappingURL=(.+)')
_JS_URL_RE = re.compile(r"""['\"](https?://[^'\"]+\.(?:js|mjs|cjs)(?:\?[^'\"]*)?)['\"]""")


def _find_source_maps(content: str) -> list[str]:
    return [m.group(1).strip() for m in _SOURCEMAP_URL_RE.finditer(content)]


def _extract_inline_source_map(data_uri: str) -> dict | None:
    try:
        header, encoded = data_uri.split(",", 1)
        if "base64" in header:
            decoded = base64.b64decode(encoded)
        else:
            decoded = urllib.request.unquote(encoded).encode("utf-8")
        return json.loads(decoded)
    except Exception:
        return None


def _extract_js_urls(files: list[Path], visited: set[str], js_only: bool) -> list[str]:
    urls: list[str] = []
    for f in files:
        if not f.is_file():
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _JS_URL_RE.finditer(content):
            url = match.group(1)
            if url not in visited:
                urls.append(url)
                visited.add(url)
    return urls


# ──────────────────────────────────────────────
# Inline <script> extraction (HTML → .inline-N.js)
# ──────────────────────────────────────────────

_HTML_SCRIPT_RE = re.compile(
    r"""<script[^>]*>\s*(//\s*<!\[CDATA\[)?\s*(.*?)\s*(//\]\]>)?\s*</script>""",
    re.IGNORECASE | re.DOTALL,
)


def _extract_html_scripts(files_dir: Path) -> int:
    """Find HTML files in *files_dir*, extract ``<script>`` bodies, and save
    them as ``<original>.inline-N.js`` alongside the originals.

    Returns the number of script blocks extracted.
    """
    extracted = 0
    for html_file in sorted(files_dir.rglob("*")):
        if not html_file.is_file():
            continue
        if html_file.suffix.lower() not in (".html", ".htm"):
            continue
        try:
            content = html_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for idx, match in enumerate(_HTML_SCRIPT_RE.finditer(content), start=1):
            script_body = match.group(2)
            if not script_body or not script_body.strip():
                continue
            # Write alongside the HTML file
            stem = html_file.stem
            dest = html_file.with_name(f"{stem}.inline-{idx}.js")
            try:
                dest.write_text(script_body, encoding="utf-8")
                extracted += 1
            except OSError:
                continue
    if extracted:
        print(color(f"[+] extracted {extracted} inline <script> block(s) from HTML", GREEN))
    return extracted


# ──────────────────────────────────────────────
# Source-map extraction (stage 5, optional)
# ──────────────────────────────────────────────

def stage_extract_source_maps(
    files_dir: Path,
    out_dir: Path,
    rate_limit: float = 5.0,
    max_per_host: int = 2,
    timeout: int = 20,
    extra_headers: dict[str, str] | None = None,
    dry_run: bool = False,
) -> Path | None:
    """Extract original sources from source maps found in downloaded files.

    Handles inline ``data:`` URIs and absolute ``http(s)://`` URLs.
    Relative URLs are resolved when *files_dir*/url_map.json exists (it
    is written by :func:`stage_download` when *js_depth* > 0).

    Returns the path to a ``sources/`` directory, or None if no source
    maps were found.
    """
    sources_dir = out_dir / "sources"
    if not dry_run:
        sources_dir.mkdir(exist_ok=True)

    if dry_run:
        js_files = list(files_dir.rglob("*"))
        print(color(f"DRY: would scan {len(js_files)} file(s) for source maps → {sources_dir}",
                    GREY))
        return sources_dir

    # Build local-path → original-URL lookup from the map written by
    # stage_download (available when js_depth > 0).
    url_map_path = files_dir / "url_map.json"
    local_to_url: dict[str, str] = {}
    if url_map_path.exists():
        url_map: dict[str, str] = json.loads(url_map_path.read_text(encoding="utf-8"))
        local_to_url = {v: k for k, v in url_map.items()}

    limiter = RateLimiter(rate_limit)
    host_limiter = HostLimiter(max_per_host)
    headers = {"User-Agent": "syck-hunt/1.0"}
    if extra_headers:
        headers.update(extra_headers)
    map_count = 0
    source_count = 0

    for js_file in sorted(files_dir.rglob("*")):
        if not js_file.is_file() or js_file.name == "url_map.json":
            continue
        try:
            content = js_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for map_ref in _find_source_maps(content):
            source_map = None

            if map_ref.startswith("data:"):
                source_map = _extract_inline_source_map(map_ref)

            elif map_ref.startswith(("http://", "https://")):
                host = urlparse(map_ref).netloc
                host_limiter.acquire(host)
                try:
                    limiter.wait()
                    req = urllib.request.Request(map_ref, headers=headers)
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        source_map = json.loads(resp.read())
                except Exception:
                    continue
                finally:
                    host_limiter.release(host)

            else:
                # Relative URL — resolve via the URL map if available
                rel = str(js_file.relative_to(files_dir))
                orig_url = local_to_url.get(rel)
                if orig_url:
                    base = orig_url.rsplit("/", 1)[0]
                    resolved = base + "/" + map_ref
                    host = urlparse(resolved).netloc
                    host_limiter.acquire(host)
                    try:
                        limiter.wait()
                        req = urllib.request.Request(resolved, headers=headers)
                        with urllib.request.urlopen(req, timeout=timeout) as resp:
                            source_map = json.loads(resp.read())
                    except Exception:
                        continue
                    finally:
                        host_limiter.release(host)

            if source_map and "sources" in source_map:
                sources = source_map.get("sources", [])
                sources_content = source_map.get("sourcesContent", [])
                for i, src_path in enumerate(sources):
                    src_content = sources_content[i] if i < len(sources_content) else ""
                    if not src_content:
                        continue
                    safe = _safe_name(src_path)
                    src_dest = sources_dir / safe
                    j = 1
                    while src_dest.exists():
                        stem, suf = src_dest.stem, src_dest.suffix
                        src_dest = sources_dir / f"{stem}_{j}{suf}"
                        j += 1
                    src_dest.write_text(src_content, encoding="utf-8")
                    source_count += 1
                map_count += 1

    if map_count:
        print(color(f"[+] extracted {source_count} source(s) from {map_count} source map(s)",
                    GREEN))
        return sources_dir

    print(color("[·] no source maps found", YELL))
    return None


# ──────────────────────────────────────────────
# Deep JS Recon (--deep-js)
# ──────────────────────────────────────────────

_DEEP_JS_PATTERNS: dict[str, tuple[str, str]] = {
    "aws_keys": ("AWS Access Key IDs",
        r"(AKIA[0-9A-Z]{16}|ABIA[0-9A-Z]{16}|ACCA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})"),
    "google_api_keys": ("Google API Keys",
        r"AIza[0-9A-Za-z\-_]{35}"),
    "google_recaptcha": ("Google reCAPTCHA Keys",
        r"6L[0-9A-Za-z\-_]{38}"),
    "firebase_urls": ("Firebase URLs",
        r"https://[a-zA-Z0-9-]+\.(?:firebaseio\.com|firebase\.com)"),
    "s3_buckets": ("S3 Buckets",
        r"[a-zA-Z0-9.\-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9.\-]+|s3-[a-zA-Z0-9\-]+\.amazonaws\.com/[a-zA-Z0-9.\-]+"),
    "internal_ips": ("Internal IPs",
        r"(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})"),
    "slack_webhooks": ("Slack Webhooks",
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
    "github_tokens": ("GitHub Tokens",
        r"(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})"),
    "private_keys": ("Private Keys",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    "emails": ("Email Addresses",
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "graphql_endpoints": ("GraphQL Endpoints",
        r"/[a-zA-Z0-9/_-]*graphql[a-zA-Z0-9/_-]*"),
    "jwt_tokens": ("JWT Tokens",
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "discord_webhooks": ("Discord Webhooks",
        r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"),
    "hardcoded_creds": ("Hardcoded Credentials",
        r"""(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth)\s*[:=]\s*["'][^"']+["']"""),
    "api_endpoints": ("API Endpoints",
        r"""(?:/api/[^"'\s<>]+|/v[0-9]+/[^"'\s<>]+)"""),
    "amazon_mws": ("Amazon MWS Auth Tokens",
        r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "paypal_braintree": ("PayPal Braintree Tokens",
        r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    "google_oauth_client_id": ("Google OAuth Client IDs",
        r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com"),
    "google_oauth_client_secret": ("Google OAuth Client Secrets",
        r"GOCSPX-[A-Za-z0-9_\-]{28}"),
    "aws_cognito": ("AWS Cognito Pool IDs",
        r"(?:us|eu|ap|sa|ca|me|af)-(?:east|west|south|north|central|southeast|northeast)-[0-9]:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "aws_appsync": ("AWS AppSync Keys",
        r"da2-[a-z0-9]{26}"),
    "gitlab_runner": ("GitLab Runner Tokens",
        r"GR1348941[A-Za-z0-9_\-]{20}"),
    "slack_app_token": ("Slack App Tokens",
        r"xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]+"),
    "shopify_custom_app": ("Shopify Custom App Tokens",
        r"shpca_[A-Fa-f0-9]{32}"),
    "new_relic_browser": ("New Relic Browser Keys",
        r"NRJS-[a-f0-9]{19}"),
    "notion_ntn": ("Notion Integration Tokens",
        r"ntn_[A-Za-z0-9]{40,}"),
    "instagram": ("Instagram Access Tokens",
        r"IGQV[A-Za-z0-9_\-]{20,}"),
    "do_spaces": ("DigitalOcean Spaces Keys",
        r"DO00[A-Z0-9]{36}"),
    "doppler": ("Doppler Tokens",
        r"dp\.(?:ct|st|sa|scim)\.[A-Za-z0-9_\-]{40,}"),
    "grafana_api": ("Grafana API Keys",
        r"glc_[A-Za-z0-9_+/]{32,}"),
    "algolia": ("Algolia API Keys",
        r"algolia[_\-]?(?:api|admin)[_\-]?key\s*[:=]\s*['\"]?[A-Za-z0-9]{32}['\"]?"),
    "credential_url": ("Credential URLs (user:pass@)",
        r"(?:https?|ftp)://[^\s:@'\"]+:[^\s:@'\"]+@[^\s'\"]+"),
}

_DEEP_JS_PATTERNS_COMPILED: dict[str, tuple[str, re.Pattern]] = {
    k: (desc, re.compile(pat)) for k, (desc, pat) in _DEEP_JS_PATTERNS.items()
}


def _js_extract_endpoints(content: str) -> set[str]:
    endpoints: set[str] = set()
    for m in re.finditer(r"""["'](/[a-zA-Z0-9_\-./]+)["']""", content):
        path = m.group(1)
        if any(ext in path for ext in ['.js', '.css', '.png', '.jpg', '.svg', '.ico', '.woff']):
            continue
        if len(path) > 4 and path.count('/') >= 1:
            endpoints.add(path)
    return endpoints


def _js_extract_variables(content: str) -> set[str]:
    found: set[str] = set()
    for m in re.finditer(r"""(?:var|let|const)\s+(\w+)\s*=\s*["']([^"']+)["']""", content):
        found.add(f"{m.group(1)} = {m.group(2)}")
    return found


def _js_extract_routes(content: str) -> set[str]:
    routes: set[str] = set()
    for m in re.finditer(
        r"""["'][/][a-zA-Z0-9_/-]*(?:admin|dashboard|manage|config|settings|internal|private|debug|api/v[0-9])[a-zA-Z0-9_/-]*["']""",
        content,
    ):
        routes.add(m.group(0).strip("\"'"))
    return routes


def _js_extract_urls(content: str) -> set[str]:
    return set(re.findall(r"""(https?://[^"'\s<>]+)""", content))


def stage_deep_js(files_dir: Path, out_dir: Path, dry_run: bool = False) -> Path | None:
    """Run deep JS extraction on all downloaded files.

    Returns the path to the JSON report, or None if nothing found.
    """
    report_path = out_dir / "deep_js_report.json"
    if dry_run or not files_dir or not files_dir.exists():
        return None

    js_files = sorted(files_dir.rglob("*"))
    if not js_files:
        return None

    print(color("[*] running deep JS recon…", CYAN), file=sys.stderr)

    results: dict[str, dict[str, list[dict]]] = {}

    for jf in js_files:
        if not jf.is_file():
            continue
        # Skip non-text files
        try:
            if b"\x00" in jf.read_bytes()[:1024]:
                continue
        except OSError:
            continue
        try:
            content = jf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        fname = str(jf.relative_to(files_dir))

        # Regex extractors
        for name, (desc, regex) in _DEEP_JS_PATTERNS_COMPILED.items():
            for m in regex.finditer(content):
                val = m.group(0).strip()
                if len(val) < 4:
                    continue
                if name not in results:
                    results[name] = {"desc": desc, "findings": []}
                results[name]["findings"].append({"value": val, "file": fname})

        # Endpoints
        for ep in _js_extract_endpoints(content):
            results.setdefault("endpoints", {"desc": "Endpoints (LinkFinder)", "findings": []})
            results["endpoints"]["findings"].append({"value": ep, "file": fname})

        # URLs
        for url in _js_extract_urls(content):
            results.setdefault("urls", {"desc": "URLs Found in JS", "findings": []})
            results["urls"]["findings"].append({"value": url, "file": fname})

        # Variables
        for var in _js_extract_variables(content):
            results.setdefault("variables", {"desc": "JS Variables", "findings": []})
            results["variables"]["findings"].append({"value": var, "file": fname})

        # Routes
        for route in _js_extract_routes(content):
            results.setdefault("routes", {"desc": "Hidden Routes", "findings": []})
            results["routes"]["findings"].append({"value": route, "file": fname})

    # Deduplicate within each category
    for cat in results:
        seen: set[str] = set()
        deduped: list[dict] = []
        for f in results[cat]["findings"]:
            if f["value"] not in seen:
                seen.add(f["value"])
                deduped.append(f)
        results[cat]["findings"] = deduped

    # Check source maps
    sourcemap_count = 0
    for jf in js_files:
        if not jf.is_file():
            continue
        map_candidate = jf.parent / (jf.name + ".map")
        if not map_candidate.exists() and jf.suffix == ".js":
            map_candidate = jf.with_suffix(".js.map")
        if map_candidate.exists():
            results.setdefault("sourcemaps", {"desc": "Source Maps Available", "findings": []})
            results["sourcemaps"]["findings"].append({
                "value": str(map_candidate.relative_to(files_dir)),
                "file": str(jf.relative_to(files_dir)),
            })
            sourcemap_count += 1

    total = sum(len(v["findings"]) for v in results.values())
    if total == 0:
        print(color("  ✔  no deep JS findings", GREEN), file=sys.stderr)
        return None

    payload = {
        "total_findings": total,
        "categories": results,
    }
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Print summary
    print(color(f"  {total} deep JS finding(s) across {len(results)} category(ies):", CYAN), file=sys.stderr)
    for cat, data in sorted(results.items(), key=lambda x: -len(x[1].get("findings", []))):
        count = len(data.get("findings", []))
        print(color(f"    {data['desc']}: {count}", GREY), file=sys.stderr)
    print(color(f"  full report → {report_path}", GREEN), file=sys.stderr)

    return report_path


# ──────────────────────────────────────────────
# Stream-JS: in-memory fetch + syck --pipe
# ──────────────────────────────────────────────

def _stream_js(urls_file: Path, out_dir: Path,
               syck_cmd: list[str],
               workers: int = 10,
               rate_limit: float = 50.0,
               max_per_host: int = 2,
               extra_headers: dict[str, str] | None = None,
               dry_run: bool = False) -> Path | None:
    """Download JS files in memory and scan with syck --pipe.
    Writes all findings to a single JSON report file.
    Returns Path to the findings JSON, or None."""
    if not urls_file or not urls_file.exists():
        return None
    urls: list[str] = []
    for line in urls_file.open(encoding="utf-8", errors="replace"):
        u = line.strip()
        if u and u.startswith(("http://", "https://")):
            urls.append(u)
    if not urls:
        print(color("[!] no URLs to stream-scan", YELL))
        return None
    out = out_dir / "05_stream_findings.json"
    if dry_run:
        return out
    limiter = RateLimiter(rate_limit)
    host_limiter = HostLimiter(max_per_host)
    all_findings: list[dict] = []
    findings_lock = threading.Lock()
    ok = 0
    fail = 0

    def _fetch_and_scan(url: str) -> None:
        nonlocal ok, fail
        host = urlparse(url).netloc or "unknown"
        host_limiter.acquire(host)
        try:
            limiter.wait()
            headers = {"User-Agent": "syck-hunt/1.0"}
            if extra_headers:
                headers.update(extra_headers)
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = resp.read()
            if not data:
                fail += 1
                return
            content = data.decode("utf-8", errors="replace")
            cmd = list(syck_cmd) + ["--pipe", url, "--format", "json"]
            result = subprocess.run(
                cmd, input=content, capture_output=True, text=True, timeout=60,
            )
            if result.stdout.strip():
                try:
                    parsed = json.loads(result.stdout)
                    if isinstance(parsed, list):
                        with findings_lock:
                            all_findings.extend(parsed)
                except json.JSONDecodeError:
                    pass
            ok += 1
        except Exception:
            fail += 1
        finally:
            host_limiter.release(host)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        pool.map(_fetch_and_scan, urls)

    # Deduplicate by rule + secret prefix
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for f in all_findings:
        key = (f.get("rule", ""), f.get("secret", "")[:60])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    out.write_text(json.dumps(deduped, indent=2), encoding="utf-8")
    print(color(f"[+] stream-scan: {ok} OK, {fail} failed, {len(deduped)} finding(s)", GREEN))
    return out


# ──────────────────────────────────────────────
# Wayback Machine / GAU integration
# ──────────────────────────────────────────────

def stage_gau(domains: list[str], out_dir: Path,
              rate_limit: float = 5.0,
              dry_run: bool = False) -> Path | None:
    """Pull URLs from Wayback Machine / GAU."""
    out = out_dir / "03_wayback_urls.txt"
    gau_path = which("gau")
    wayback_path = which("wayback")

    if not gau_path and not wayback_path:
        print(color("[!] 'gau' or 'wayback' required for --wayback mode", RED))
        print(color("    Install:  go install github.com/lc/gau/v2/cmd/gau@latest", YELL))
        print(color("    Or:       go install github.com/tomnomnom/waybackurls@latest", YELL))
        return None

    if gau_path:
        print(color(f"[*] fetching Wayback URLs with gau for {len(domains)} domain(s)", CYAN))
        args = ["gau", "--o", str(out), "--threads", "10"]
        if rate_limit > 0:
            args += ["--rate-limit", str(int(rate_limit))]
        args.extend(domains)
    else:
        print(color(f"[*] fetching Wayback URLs with waybackurls for {len(domains)} domain(s)", CYAN))
        dlist = out_dir / "wayback_domains.txt"
        if not dry_run:
            dlist.write_text("\n".join(domains) + "\n", encoding="utf-8")
        args = ["bash", "-c", f"cat {dlist} | waybackurls > {out}"]

    rc = run_cmd(args, dry_run)
    if dry_run:
        return out
    if rc != 0 or not out.exists() or out.stat().st_size == 0:
        print(color("[!] gau/wayback produced no output", YELL))
        return None
    n = sum(1 for _ in out.open(encoding="utf-8", errors="replace"))
    print(color(f"[+] {n} Wayback URL(s)", GREEN))
    return out
