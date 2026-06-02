#!/usr/bin/env python3
"""
syck-hunt.py — scan a website's source code for exposed secrets.

Default pipeline:

    target  →  httpx  →  katana  →  download JS  →  syck

  - httpx resolves the target and confirms it's live
  - katana crawls it and produces a URL list
  - the downloader fetches the JS (or all crawled files)
  - syck scans the downloaded source for exposed secrets

Subdomain enumeration with subfinder is **opt-in** (`-es`).
Add it when you also want to scan the subdomains of the target.

Each stage writes its output to the run directory so you can inspect or
re-run individual stages manually.

Usage:
  syck-hunt target.com                       # scan target.com
  syck-hunt target.com -es                   # also enumerate subdomains
  syck-hunt target.com -nk                   # probe + download, no crawl
  syck-hunt -l domains.txt -o ./recon -f sarif
  syck-hunt -so ./leaked-repo -s CRITICAL
  syck-hunt -ct                              # check dependencies
  syck-hunt target.com -dr                   # dry-run
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

# ──────────────────────────────────────────────
# Tiny colour helpers (no colorama dep)
# ──────────────────────────────────────────────
RESET = "\033[0m"
BOLD  = "\033[1m"
RED   = "\033[91m"
GREEN = "\033[93m" if False else "\033[92m"
YELL  = "\033[93m"
CYAN  = "\033[96m"
GREY  = "\033[90m"

USE_COLOR = sys.stdout.isatty()


BANNER = """\
=================================================
 syck-hunt — target → httpx → katana → syck
 {timestamp}
=================================================
"""


def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if USE_COLOR else text


def hr(char: str = "─", n: int = 60) -> str:
    return char * n


# ──────────────────────────────────────────────
# Rate limiting (to avoid DoS'ing the target)
# ──────────────────────────────────────────────

class RateLimiter:
    """Global token-bucket-ish limiter.  `rps=0` disables it."""

    def __init__(self, rps: float):
        self.rps = float(rps)
        self.min_interval = (1.0 / self.rps) if self.rps > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delay = self.min_interval - (now - self._last)
            if delay > 0:
                time.sleep(delay)
            self._last = time.monotonic()


class HostLimiter:
    """Per-host concurrency cap (e.g. 2 simultaneous requests to the same host)."""

    def __init__(self, max_per_host: int):
        self.max = max(1, int(max_per_host))
        self._sems: dict[str, threading.Semaphore] = {}
        self._lock = threading.Lock()

    def acquire(self, host: str) -> None:
        with self._lock:
            sem = self._sems.setdefault(host, threading.Semaphore(self.max))
        sem.acquire()

    def release(self, host: str) -> None:
        with self._lock:
            sem = self._sems.get(host)
        if sem is not None:
            sem.release()


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
# Tool / config tables
# ──────────────────────────────────────────────
TOOL_URLS = {
    "subfinder": "https://github.com/projectdiscovery/subfinder/releases",
    "httpx":     "https://github.com/projectdiscovery/httpx/releases",
    "katana":    "https://github.com/projectdiscovery/katana/releases",
    "syck":      "this repo (syck.py, see the README)",
}


def which(name: str) -> str | None:
    return shutil.which(name)


def check_tools(skip_katana: bool = False, want_subfinder: bool = False) -> bool:
    """Print which tools are present and warn about anything missing.

    `syck` is NOT in the required list — the final scan stage is a soft
    dependency.  If it's not on PATH, the recon stages still run and we
    just skip the syck step with a clear "how to add it" hint.  Pass
    --syck-path to point at the script directly.

    Set `want_subfinder=True` when the caller has asked for subdomain
    enumeration via --enum-subs; in the default flow subfinder isn't
    needed and isn't checked.
    """
    required = ["httpx"]
    if not skip_katana:
        required.append("katana")
    if want_subfinder:
        required.append("subfinder")
    print(color("Tool check:", BOLD))
    ok = True
    for t in required:
        path = which(t)
        if path:
            print(color(f"  [✓] {t:<11} {path}", GREEN))
        else:
            print(color(f"  [✗] {t:<11} not found in PATH", RED))
            ok = False
    syck_path = which("syck")
    if syck_path:
        print(color(f"  [✓] {'syck':<11} {syck_path}", GREEN))
    else:
        print(color("  [·] syck        not on PATH (scan stage will be skipped)", YELL))
        print(color(f"         {TOOL_URLS['syck']}", GREY))
        print(color("         or pass --syck-path /full/path/to/syck.py", GREY))
    if not ok:
        print(color("\nInstall missing tools:", YELL))
        for t, url in TOOL_URLS.items():
            if t == "syck":
                continue
            if t == "subfinder" and not want_subfinder:
                continue
            if which(t) is None:
                print(color(f"  {t}: {url}", GREY))
    return ok


# ──────────────────────────────────────────────
# Stage runners
# ──────────────────────────────────────────────

def run_cmd(args: list[str], dry_run: bool = False) -> int:
    print(color(f"\n$ {' '.join(str(a) for a in args)}", GREY))
    if dry_run:
        return 0
    try:
        return subprocess.call(args)
    except FileNotFoundError as e:
        print(color(f"[!] command not found: {e}", RED), file=sys.stderr)
        return 127


def stage_subfinder(domains: list[str], out_dir: Path,
                    dry_run: bool = False) -> Path | None:
    """Stage 1: enumerate subdomains."""
    out = out_dir / "01_subdomains.txt"
    if len(domains) == 1:
        args = ["subfinder", "-d", domains[0], "-silent", "-all", "-o", str(out)]
    else:
        dlist = out_dir / "domains.txt"
        dlist.write_text("\n".join(domains), encoding="utf-8")
        args = ["subfinder", "-dL", str(dlist), "-silent", "-all", "-o", str(out)]
    rc = run_cmd(args, dry_run)
    if dry_run:
        return out
    if rc != 0 or not out.exists() or out.stat().st_size == 0:
        print(color("[!] subfinder produced no output", YELL))
        return None
    n = sum(1 for _ in out.open(encoding="utf-8", errors="replace"))
    print(color(f"[+] {n} subdomain(s)", GREEN))
    return out


def stage_httpx(subs_file: Path, out_dir: Path,
                rate_limit: float = 5.0,
                dry_run: bool = False) -> Path | None:
    """Stage 2: probe for live HTTP services."""
    raw = out_dir / "02_live_hosts.txt"
    args = ["httpx", "-l", str(subs_file), "-silent", "-o", str(raw),
            "-status-code", "-title"]
    if rate_limit > 0:
        # httpx: -rate-limit is in milliseconds between requests
        args += ["-rate-limit", str(int(1000 / rate_limit))]
    rc = run_cmd(args, dry_run)
    if rc != 0 or not raw.exists() or raw.stat().st_size == 0:
        if dry_run:
            return out_dir / "02_live_urls.txt"
        print(color("[!] httpx found no live hosts", YELL))
        return None
    # httpx-with-flags output is "<url> [<code>] [<title>]"; keep just URLs
    urls = out_dir / "02_live_urls.txt"
    if dry_run:
        return urls
    with urls.open("w", encoding="utf-8") as dst:
        for line in raw.open(encoding="utf-8", errors="replace"):
            first = line.split()[0] if line.strip() else ""
            if first:
                dst.write(first + "\n")
    n = sum(1 for _ in urls.open(encoding="utf-8", errors="replace"))
    print(color(f"[+] {n} live host(s)", GREEN))
    return urls


def stage_katana(hosts_file: Path, out_dir: Path, depth: int = 2,
                 rate_limit: float = 5.0, concurrency: int = 10,
                 dry_run: bool = False) -> Path | None:
    """Stage 3: crawl the live hosts."""
    out = out_dir / "03_urls.txt"
    args = ["katana", "-list", str(hosts_file), "-silent",
            "-d", str(depth), "-o", str(out), "-kf", "all",
            "-concurrency", str(concurrency)]
    if 0 < rate_limit <= 1:
        # katana: -rate-limit is INTEGER seconds per host.  For any
        # rate faster than 1 rps the value would round to 0 (and
        # katana rejects non-integer strings with 'parse error'),
        # so we only pass it for slow scans.  For faster scans the
        # downloader's token-bucket per-second limit does the
        # throttling.
        args += ["-rate-limit", str(round(1.0 / rate_limit))]
    rc = run_cmd(args, dry_run)
    if dry_run:
        return out
    if rc != 0 or not out.exists() or out.stat().st_size == 0:
        print(color("[!] katana found no URLs", YELL))
        return None
    n = sum(1 for _ in out.open(encoding="utf-8", errors="replace"))
    print(color(f"[+] {n} URL(s) crawled", GREEN))
    return out


def _safe_name(url: str) -> str:
    last = url.split("?", 1)[0].rsplit("/", 1)[-1] or "index.html"
    name = "".join(c for c in last if c.isalnum() or c in "._-")
    if not name:
        return "index.html"
    return name[:80]


def _download_one(url: str, dest_dir: Path,
                  limiter: RateLimiter, host_limiter: HostLimiter,
                  timeout: int = 20, retries: int = 2,
                  extra_headers: dict[str, str] | None = None) -> Path | None:
    name = _safe_name(url)
    dest = dest_dir / name
    i = 1
    while dest.exists():
        stem, suf = dest.stem, dest.suffix
        dest = dest_dir / f"{stem}_{i}{suf}"
        i += 1
    host = urlparse(url).netloc or "unknown"

    # Build request headers
    headers = {"User-Agent": "syck-hunt/1.0"}
    if extra_headers:
        headers.update(extra_headers)

    for attempt in range(retries + 1):
        host_limiter.acquire(host)
        try:
            limiter.wait()
            req = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = resp.read()
                if not data:
                    return None
                dest.write_bytes(data)
                return dest
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
                if attempt < retries:
                    delay = 2 ** attempt
                    if USE_COLOR:
                        print(color(f"  [retry {attempt + 1}/{retries}] {url} "
                                    f"failed ({exc}), waiting {delay}s…", YELL),
                              file=sys.stderr)
                    time.sleep(delay)
                    continue
                return None
        finally:
            host_limiter.release(host)
    return None


_HTML_SCRIPT_RE = re.compile(
    r"""<script[^>]*>\s*(//\s*<!\[CDATA\[)?\s*(.*?)\s*(//\]\]>)?\s*</script>""",
    re.IGNORECASE | re.DOTALL,
)


def stage_download(urls_file: Path, out_dir: Path, max_files: int = 200,
                   workers: int = 10, js_only: bool = True,
                   rate_limit: float = 5.0, max_per_host: int = 2,
                   js_depth: int = 0, extract_scripts: bool = False,
                   extra_headers: dict[str, str] | None = None,
                   dry_run: bool = False) -> Path | None:
    """Stage 4: download JS files for offline scanning.

    When *js_depth* > 0, downloaded JS files are parsed for import/require
    URLs and those are fetched recursively up to *js_depth* levels deep.

    When *extract_scripts* is True, HTML files are parsed for inline
    ``<script>`` blocks and saved alongside downloaded JS.
    """
    files_dir = out_dir / "downloaded"
    files_dir.mkdir(exist_ok=True)

    if not urls_file or not urls_file.exists():
        return None

    urls: list[str] = []
    for line in urls_file.open(encoding="utf-8", errors="replace"):
        u = line.strip()
        if not u or not u.startswith(("http://", "https://")):
            continue
        if js_only and ".js" not in u.lower():
            continue
        urls.append(u)

    if not urls:
        print(color("[!] no URLs matched the filter", YELL))
        return None

    visited: set[str] = set()
    url_map: dict[str, str] = {}
    limiter = RateLimiter(rate_limit)
    host_limiter = HostLimiter(max_per_host)
    all_ok = 0

    current_batch = urls[:max_files]

    for level in range(js_depth + 1):
        if not current_batch:
            break
        if level > 0:
            print(color(f"[*] recursion depth {level}: {len(current_batch)} new URL(s)", CYAN))

        if dry_run:
            rps = f"{rate_limit} req/s" if rate_limit > 0 else "unlimited"
            print(color(
                f"DRY [depth {level}]: would download {len(current_batch)} URL(s) → {files_dir} "
                f"({workers} workers, {rps}, ≤{max_per_host}/host)",
                GREY,
            ))
            # Still need to mark visited so dry-run follows the correct path
            visited.update(current_batch)
            if level < js_depth:
                current_batch = [u for u in current_batch if u not in visited][:max_files]
            continue

        rps = f"{rate_limit} req/s" if rate_limit > 0 else "unlimited"
        print(color(
            f"[*] downloading {len(current_batch)} URL(s) — {workers} workers, {rps}, "
            f"≤{max_per_host}/host…", CYAN,
        ))
        batch_ok = 0
        batch_downloaded: list[Path] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
            futs = {exe.submit(_download_one, u, files_dir, limiter, host_limiter,
                               extra_headers=extra_headers): u
                    for u in current_batch}
            for fut in concurrent.futures.as_completed(futs):
                u = futs[fut]
                visited.add(u)
                result = fut.result()
                if result is not None:
                    batch_ok += 1
                    batch_downloaded.append(result)
                    url_map[u] = str(result.relative_to(files_dir))
        all_ok += batch_ok
        print(color(f"[+] {batch_ok}/{len(current_batch)} downloaded", GREEN))

        if level < js_depth:
            new_urls = _extract_js_urls(batch_downloaded, visited, js_only)
            current_batch = [u for u in new_urls if u not in visited][:max_files]

    # Store URL map so source-map extraction can resolve relative URLs
    if url_map and not dry_run:
        (files_dir / "url_map.json").write_text(json.dumps(url_map, indent=2), encoding="utf-8")

    # Extract inline <script> blocks from downloaded HTML files
    if extract_scripts and not dry_run and all_ok > 0:
        _extract_html_scripts(files_dir)

    if dry_run:
        return files_dir if urls else None
    return files_dir if all_ok > 0 else None


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


def stage_syck(targets: Iterable[Path], out_dir: Path,
               severity: str = "LOW", fmt: str = "text",
               redact: bool = False, workers: int = 4,
               max_file_size: str = "5M",
               syck_cmd: list[str] | None = None,
               dry_run: bool = False) -> Path | None:
    """Stage 5: scan downloaded files with syck.

    `syck_cmd` lets the caller override the executable — by default we
    try `syck` on PATH.  Pass `["python3", "/path/to/syck.py"]` (or
    similar) when syck isn't on PATH.  Returns None if syck is not
    available; caller is expected to surface a hint in that case.

    For fmt='text' the report is also printed to stdout after syck
    finishes (terminal-friendly).  For other formats the report is
    written to a file and the path is shown — pass -f text if you
    want the report in your terminal.
    """
    targets = [t for t in targets if t is not None]
    if not targets:
        return None
    if syck_cmd is None:
        syck_cmd = ["syck"]
    ext = "html" if fmt == "html" else fmt
    out = out_dir / f"04_syck_report.{ext}"
    args = [*syck_cmd, *[str(t) for t in targets],
            "--format", fmt, "-o", str(out),
            "--severity", severity,
            "--workers", str(workers),
            "--max-file-size", max_file_size]
    if redact:
        args.append("--redact")
    if dry_run:
        print(color(f"DRY: {' '.join(str(a) for a in args)}", GREY))
        return out
    rc = run_cmd(args, dry_run)
    if rc not in (0, 1) or not out.exists():
        print(color("[!] syck did not produce a report", YELL))
        return None
    print(color(f"[+] report → {out}", GREEN))
    if fmt == "text":
        # Stream the report to the terminal so the user can see findings
        # without having to open the file.  ANSI codes survive the
        # round-trip because they're written verbatim.
        print()
        print(color("═" * 60, GREY))
        print(color(f"  syck report ({out})", BOLD))
        print(color("═" * 60, GREY))
        print(out.read_text(encoding="utf-8", errors="replace"))
    return out


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
# CLI
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="syck-hunt",
        description=(
            "Scan a website's source code (HTML, JS, JSON, …) for "
            "exposed secrets.\n\n"
            "Pipeline:  domain  →  httpx  →  katana  →  download  →  syck"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
shortcuts:
  -d   --depth              -mf  --max-files        -r   --redact
  -o   --output-dir         -s   --severity         -ct  --check-tools
  -f   --format             -w   --workers          -dr  --dry-run
  -l   --list               -rl  --rate-limit       -nc  --no-color
  -sp  --syck-path          -mc  --max-concurrent   -nk  --no-katana
  -so  --scan-only          -kc  --katana-conc      -nd  --no-download
  -es  --enum-subs          -dw  --download-workers -mfs --max-file-size
  -js  --js-only            -aj  --all-files          -jsd --js-depth
  -sm  --extract-source-maps      -xs  --extract-scripts
  --header NAME:VALUE      --cookie COOKIE

examples:
  syck-hunt target.com
  syck-hunt target.com -es                  # also enumerate subdomains
  syck-hunt target.com -nk                  # probe + download, no crawl
  syck-hunt target.com -jsd 2               # recursively follow JS imports
  syck-hunt target.com -sm                  # extract source maps + scan sources
  syck-hunt -l domains.txt -o ./recon -f sarif
  syck-hunt -so ./leaked-repo -s CRITICAL
  syck-hunt -ct
  syck-hunt target.com -dr
""",
    )

    ap.add_argument("domains", nargs="*",
                    help="Target domain(s) — e.g. example.com")
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="File with one domain per line")

    out = ap.add_argument_group("output")
    out.add_argument("-o", "--output-dir", default="./recon",
                     help="Output root (default: ./recon)")
    out.add_argument("-s", "--severity",
                     choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                     default="LOW", help="Min syck severity (default: LOW)")
    out.add_argument("-f", "--format",
                     choices=["text", "json", "sarif", "markdown",
                              "csv", "html"], default="text",
                     help="Report format (default: text — printed to terminal "
                          "after the scan; use html/json/sarif for files)")
    out.add_argument("-r", "--redact", action="store_true",
                     help="Mask secrets in the report (default: shown in full)")

    stages = ap.add_argument_group("recon stages")
    stages.add_argument("-es", "--enum-subs", action="store_true",
                        help="Enable subdomain enumeration with subfinder "
                             "(default: off, scan only the input domain)")
    stages.add_argument("-nk", "--no-katana", action="store_true",
                        help="Skip katana crawl (probe-only)")
    stages.add_argument("-nd", "--no-download", action="store_true",
                        help="Skip JS download (crawl-only)")
    stages.add_argument("-js", "--js-only", action="store_true", default=True,
                        help="Download only .js files (default: on)")
    stages.add_argument("-aj", "--all-files", dest="js_only",
                        action="store_false",
                        help="Download all crawled URLs, not just .js")
    stages.add_argument("-xs", "--extract-scripts", action="store_true",
                        help="Extract inline <script> blocks from HTML files and scan them")

    crawl = ap.add_argument_group("crawl tuning")
    crawl.add_argument("-d", "--depth", type=int, default=2,
                       help="Katana crawl depth (default: 2)")
    crawl.add_argument("-mf", "--max-files", type=int, default=200,
                       help="Max files to download (default: 200)")
    crawl.add_argument("-dw", "--download-workers", type=int, default=10,
                       help="Concurrent download workers (default: 10)")
    crawl.add_argument("-mfs", "--max-file-size", default="5M",
                       help="Max size per scanned file (default: 5M)")
    crawl.add_argument("-jsd", "--js-depth", type=int, default=0,
                       metavar="N",
                       help="Recursively follow JS imports up to depth N "
                            "(default: 0 — no recursion)")
    crawl.add_argument("--header", action="append", default=[],
                       metavar="NAME:VALUE",
                       help="Add a custom HTTP header to all requests "
                            "(repeatable, e.g. --header 'Authorization: Bearer x')")
    crawl.add_argument("--cookie", metavar="COOKIE",
                       help="Cookie header value for all requests "
                            "(e.g. 'session=abc123')")

    rate = ap.add_argument_group("rate limiting")
    rate.add_argument("-rl", "--rate-limit", type=float, default=50.0,
                      metavar="RPS",
                      help="Max requests/sec across all stages "
                           "(default: 50, 0 to disable)")
    rate.add_argument("-mc", "--max-concurrent", type=int, default=5,
                      metavar="N",
                      help="Max simultaneous requests per host (default: 5)")
    rate.add_argument("-kc", "--katana-conc", type=int, default=20,
                      metavar="N", help="katana -concurrency (default: 20)")

    scan = ap.add_argument_group("scanning")
    scan.add_argument("-so", "--scan-only", metavar="PATH",
                      help="Skip recon, run syck directly on PATH "
                           "(file or dir)")
    scan.add_argument("-w", "--workers", type=int, default=4,
                      dest="syck_workers",
                      help="syck --workers (default: 4)")
    scan.add_argument("-sp", "--syck-path", metavar="PATH",
                      help="Path to syck.py (or 'syck' binary). "
                           "Use this if syck isn't on $PATH.")
    scan.add_argument("-sm", "--extract-source-maps", action="store_true",
                      help="Extract original sources from source maps "
                           "and scan them for secrets")

    misc = ap.add_argument_group("misc")
    misc.add_argument("-ct", "--check-tools", action="store_true",
                      help="Check which dependencies are present and exit")
    misc.add_argument("-dr", "--dry-run", action="store_true",
                      help="Print commands without executing them")
    misc.add_argument("-nc", "--no-color", action="store_true",
                      help="Disable coloured output")
    return ap


def main(argv: list[str] | None = None) -> int:
    global USE_COLOR
    args = build_parser().parse_args(argv)
    if args.no_color:
        USE_COLOR = False

    print(color(BANNER.format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                BOLD))

    if args.check_tools:
        return 0 if check_tools(skip_katana=args.no_katana,
                                want_subfinder=args.enum_subs) else 1

    domains: list[str] = list(args.domains or [])
    if args.list:
        domains.extend(
            line.strip() for line in Path(args.list).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        )
    if not domains and not args.scan_only:
        print(color("error: provide a domain or --list/--scan-only", RED),
              file=sys.stderr)
        return 2

    # Build per-target output directory
    if args.scan_only:
        target_label = Path(args.scan_only).resolve().name
    else:
        target_label = domains[0] if len(domains) == 1 else f"multi_{len(domains)}"
    out_dir = Path(args.output_dir) / target_label
    out_dir.mkdir(parents=True, exist_ok=True)
    print(color(f"[*] run directory: {out_dir}", CYAN))

    # Build extra HTTP headers from --header and --cookie
    extra_headers: dict[str, str] = {}
    for hdr in getattr(args, "header", []) or []:
        if ":" in hdr:
            key, val = hdr.split(":", 1)
            extra_headers[key.strip()] = val.strip()
    if getattr(args, "cookie", None):
        extra_headers["Cookie"] = args.cookie

    # In scan-only mode the recon tools (subfinder/httpx/katana) aren't
    # needed — just print the tool check and continue.  In full-recon
    # mode, missing tools are a hard fail.
    if args.scan_only:
        check_tools(skip_katana=True)
    else:
        if not check_tools(skip_katana=args.no_katana,
                            want_subfinder=args.enum_subs):
            if not args.dry_run:
                return 1

    # Mode 1: scan-only
    if args.scan_only:
        syck_cmd = _resolve_syck(args, interactive=not args.dry_run)
        if syck_cmd is None:
            return _summarise(out_dir, None, args.dry_run)
        report = stage_syck(
            targets=[Path(args.scan_only)],
            out_dir=out_dir,
            severity=args.severity,
            fmt=args.format,
            redact=args.redact,
            workers=args.syck_workers,
            max_file_size=args.max_file_size,
            syck_cmd=syck_cmd,
            dry_run=args.dry_run,
        )
        return _summarise(out_dir, report, args.dry_run)

    # Mode 2: full recon → download → syck
    if args.enum_subs:
        print(color(f"[*] -es: enumerating subdomains for {len(domains)} "
                    f"target domain(s) with subfinder", CYAN))
        subs = stage_subfinder(domains, out_dir, dry_run=args.dry_run)
    else:
        # Default: skip subdomain enumeration.  Write the input domains
        # straight to a file in subfinder's slot — stage_httpx doesn't
        # care where the host list came from.
        subs = out_dir / "00_targets.txt"
        if not args.dry_run:
            subs.write_text("\n".join(domains) + "\n", encoding="utf-8")
    if not subs and not args.dry_run:
        return _summarise(out_dir, None, args.dry_run)

    hosts = stage_httpx(subs, out_dir,
                        rate_limit=args.rate_limit,
                        dry_run=args.dry_run)
    if not hosts and not args.dry_run:
        return _summarise(out_dir, None, args.dry_run)

    if args.no_katana:
        return _summarise(out_dir, None, args.dry_run)

    urls = stage_katana(hosts, out_dir,
                        depth=args.depth,
                        rate_limit=args.rate_limit,
                        concurrency=args.katana_conc,
                        dry_run=args.dry_run)
    if not urls and not args.dry_run:
        return _summarise(out_dir, None, args.dry_run)

    if args.no_download:
        print(color("\n[✓] recon complete (download skipped)", GREEN))
        return _summarise(out_dir, None, args.dry_run)

    files = stage_download(
        urls, out_dir,
        max_files=args.max_files,
        workers=args.download_workers,
        js_only=args.js_only,
        rate_limit=args.rate_limit,
        max_per_host=args.max_concurrent,
        js_depth=args.js_depth,
        extract_scripts=args.extract_scripts,
        extra_headers=extra_headers or None,
        dry_run=args.dry_run,
    )
    if not files and not args.dry_run:
        return _summarise(out_dir, None, args.dry_run)

    # Optional: extract sources from source maps
    sources: Path | None = None
    if args.extract_source_maps and files:
        sources = stage_extract_source_maps(
            files, out_dir,
            rate_limit=args.rate_limit,
            max_per_host=args.max_concurrent,
            extra_headers=extra_headers or None,
            dry_run=args.dry_run,
        )

    syck_cmd = _resolve_syck(args, interactive=not args.dry_run)
    if syck_cmd is None:
        return _summarise(out_dir, None, args.dry_run)

    # Build syck targets: downloaded files + extracted sources
    syck_targets: list[Path] = []
    if files:
        syck_targets.append(files)
    if sources:
        syck_targets.append(sources)
    if not syck_targets:
        syck_targets = [out_dir]

    report = stage_syck(
        targets=syck_targets,
        out_dir=out_dir,
        severity=args.severity,
        fmt=args.format,
        redact=args.redact,
        workers=args.syck_workers,
        max_file_size=args.max_file_size,
        syck_cmd=syck_cmd,
        dry_run=args.dry_run,
    )
    return _summarise(out_dir, report, args.dry_run)


def _summarise(out_dir: Path, report: Path | None, dry_run: bool) -> int:
    print(color("\n" + hr("═"), BOLD))
    print(color(" Pipeline summary", BOLD))
    print(color(hr("═"), BOLD))
    for f in sorted(out_dir.iterdir()):
        rel = str(f.relative_to(out_dir))
        if f.is_file():
            size = f.stat().st_size
            print(f"  {rel:<30}  {size:>8} bytes")
        elif f.is_dir():
            count = sum(1 for _ in f.rglob("*") if _.is_file())
            print(f"  {rel}/  ({count} file(s))")
    if report:
        print(color(f"\n[✓] final report: {report}", GREEN))
    elif not dry_run:
        print(color("\n[i] recon complete, no scan run", YELL))
    return 0


def _resolve_syck(args, interactive: bool) -> list[str] | None:
    """Figure out how to invoke syck.  Returns a command list, or None.

    Resolution order:
      1. --syck-path (explicit, may point to .py or a binary)
      2. `syck` on $PATH
      3. Friendly hint + return None
    """
    if args.syck_path:
        p = Path(args.syck_path)
        if not p.exists():
            print(color(f"[!] --syck-path {p} does not exist", RED),
                  file=sys.stderr)
            return None
        # .py file → invoke via python
        if p.suffix == ".py":
            return [sys.executable, str(p)]
        return [str(p)]
    if which("syck"):
        return ["syck"]
    if interactive:
        print(color("\n[!] 'syck' is not on $PATH — skipping the scan stage.", YELL))
        print(color("    To enable it, pick one:", YELL))
        print(color("      a) Symlink the script:    ln -s /path/to/syck.py ~/bin/syck", YELL))
        print(color("      b) Add the script dir to PATH in ~/.zshenv:", YELL))
        print(color("           export PATH=\"$HOME/secretsyoucantkeep:$PATH\"", YELL))
        print(color("      c) Pass it explicitly:    --syck-path /path/to/syck.py", YELL))
    return None


if __name__ == "__main__":
    raise SystemExit(main())
