"""syck.hunt.stages — pipeline stage runners (subfinder → httpx → katana → download → syck)."""
from __future__ import annotations

import concurrent.futures
import hashlib
import http.client
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from syck.hunt import utils
from syck.hunt.recon import _extract_html_scripts, _extract_js_urls
from syck.hunt.utils import (
    BOLD, CHECKPOINT_FILE, CYAN, GREEN, GREY, RED, YELL,
    HostLimiter, RateLimiter,
    _safe_name, color, hr, run_cmd,
)

# ──────────────────────────────────────────────
# Stage runners
# ──────────────────────────────────────────────

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
                 headless: bool = False,
                 dry_run: bool = False) -> Path | None:
    """Stage 3: crawl the live hosts."""
    out = out_dir / "03_urls.txt"
    args = ["katana", "-list", str(hosts_file), "-silent",
            "-d", str(depth), "-o", str(out), "-kf", "all",
            "-concurrency", str(concurrency)]
    if headless:
        args.append("-headless")
    if rate_limit > 0 and rate_limit < 1:
        # katana: -rate-limit is INTEGER seconds per host.  For rates
        # >= 1 req/s the interval would round to 0, so we skip it and
        # let the downloader's token bucket handle throttling.
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


def _download_one(url: str, dest_dir: Path,
                  limiter: RateLimiter, host_limiter: HostLimiter,
                  timeout: int = 20, retries: int = 2,
                  extra_headers: dict[str, str] | None = None,
                  filter_content_type: bool = False) -> Path | None:
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

    # HEAD pre-filter: skip if Content-Type is not acceptable
    if filter_content_type and not _content_type_acceptable(url, extra_headers):
        return None

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
            except (urllib.error.URLError, TimeoutError, OSError, ValueError,
                     http.client.IncompleteRead) as exc:
                if attempt < retries:
                    delay = 2 ** attempt
                    if utils.USE_COLOR:
                        print(color(f"  [retry {attempt + 1}/{retries}] {url} "
                                    f"failed ({exc}), waiting {delay}s…", YELL),
                              file=sys.stderr)
                    time.sleep(delay)
                    continue
                return None
        finally:
            host_limiter.release(host)
    return None


# Content-Type accept filter for the HEAD pre-filter
_ACCEPTED_CONTENT_TYPES = re.compile(
    r"(?i)(text/|application/javascript|application/json|"
    r"application/x-javascript|application/ecmascript)"
)


def _content_type_acceptable(url: str, extra_headers: dict[str, str] | None = None,
                             timeout: int = 10) -> bool:
    """Send a HEAD request and check if Content-Type is acceptable.
    Returns True if the Content-Type is missing or matches accepted types,
    False otherwise.  Non-fatal errors (timeout, connection refused) also
    return True so the caller still attempts the GET."""
    try:
        headers = {"User-Agent": "syck-hunt/1.0"}
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(url, headers=headers, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
        if not ct:
            return True
        return bool(_ACCEPTED_CONTENT_TYPES.search(ct))
    except Exception:
        return True


def _dedup_files(target_dir: Path) -> int:
    """Remove duplicate files in *target_dir* based on SHA256 content hash.

    Keeps the first file seen for each hash.  Returns the number of files
    removed.  Skips url_map.json and hidden files (dotfiles).
    """
    seen: dict[str, Path] = {}
    removed = 0
    for p in sorted(target_dir.iterdir()):
        if not p.is_file() or p.name.startswith(".") or p.name == "url_map.json":
            continue
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        if h in seen:
            p.unlink()
            removed += 1
        else:
            seen[h] = p
    return removed


def stage_async_download(urls_file: Path, out_dir: Path, max_files: int = 200,
                         workers: int = 10, js_only: bool = True,
                         filter_content_type: bool = False,
                         extra_headers: dict[str, str] | None = None,
                         dry_run: bool = False) -> Path | None:
    """Stage 4a: async download JS files using aiohttp + SQLite cache.
    Returns the downloaded files directory, same interface as stage_download."""
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
    if dry_run:
        print(color(f"DRY: would async-download {len(urls)} URL(s) → {files_dir} "
                    f"({workers} workers)", GREY))
        return files_dir if urls else None
    print(color(f"[*] async-downloading {len(urls)} URL(s) — {workers} workers"
                f"{', HEAD filter' if filter_content_type else ''}…", CYAN))
    try:
        from syck.async_fetch import URLContentCache, fetch_urls_async
        cache = URLContentCache()
        fetched: list[Path] = fetch_urls_async(
            urls, files_dir, max_concurrent=workers,
            cache=cache, filter_content_type=filter_content_type,
        )
        cache.close()
    except ImportError:
        print(color("[!] syck_async.py not found, falling back to threaded download", YELL))
        from syck.async_fetch import fetch_urls_threaded
        cache = URLContentCache()
        fetched = fetch_urls_threaded(
            urls, files_dir, workers=workers,
            cache=cache, filter_content_type=filter_content_type,
        )
        cache.close()
    if fetched:
        print(color(f"[+] {len(fetched)}/{len(urls)} downloaded", GREEN))
    return files_dir if fetched else None


def stage_download(urls_file: Path, out_dir: Path, max_files: int = 200,
                   workers: int = 10, js_only: bool = True,
                   rate_limit: float = 5.0, max_per_host: int = 2,
                   js_depth: int = 0, extract_scripts: bool = False,
                   extra_headers: dict[str, str] | None = None,
                   filter_content_type: bool = False,
                   dry_run: bool = False) -> Path | None:
    """Stage 4: download JS files for offline scanning.

    When *js_depth* > 0, downloaded JS files are parsed for import/require
    URLs and those are fetched recursively up to *js_depth* levels deep.

    When *extract_scripts* is True, HTML files are parsed for inline
    ``<script>`` blocks and saved alongside downloaded JS.

    When *filter_content_type* is True, a HEAD request is sent first
    and only URLs with JavaScript/HTML/JSON content types are downloaded.
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
                               extra_headers=extra_headers,
                               filter_content_type=filter_content_type): u
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

    # Deduplicate files by content hash
    if not dry_run and all_ok > 0:
        dupes = _dedup_files(files_dir)
        if dupes:
            print(color(f"[+] removed {dupes} duplicate(s) by content hash", GREEN))

    # Rebuild url_map from remaining files, then store it
    if url_map and not dry_run:
        for url, rel in list(url_map.items()):
            if not (files_dir / rel).exists():
                del url_map[url]
        (files_dir / "url_map.json").write_text(json.dumps(url_map, indent=2), encoding="utf-8")

    # Extract inline <script> blocks from downloaded HTML files
    if extract_scripts and not dry_run and all_ok > 0:
        _extract_html_scripts(files_dir)

    if dry_run:
        return files_dir if urls else None
    return files_dir if all_ok > 0 else None


def stage_probe(urls_file: Path, out_dir: Path,
                rate_limit: float = 50.0,
                dry_run: bool = False) -> Path | None:
    """Filter crawled URLs to only 200 OK responses via httpx -mc 200.
    Returns Path to the filtered URL file, or None."""
    if not urls_file or not urls_file.exists():
        return None
    out = out_dir / "04_live_urls.txt"
    if dry_run:
        return out
    cmd = [
        "httpx", "-l", str(urls_file), "-o", str(out),
        "-mc", "200", "-silent", "-retries", "1", "-timeout", "10",
        "-rl", str(int(rate_limit)) if rate_limit > 0 else "0",
    ]
    subprocess.run(cmd, check=False)
    if out.exists() and out.stat().st_size > 0:
        n = len(out.read_text(encoding="utf-8").splitlines())
        print(color(f"[+] {n} live URL(s) after probe filter", GREEN))
        return out
    return None


def stage_extract_js_urls(crawled_urls_file: Path, out_dir: Path,
                           downloaded_dir: Path | None = None,
                           dry_run: bool = False) -> Path | None:
    """Extract JS URLs from crawled HTML/JS content using regex patterns.
    Writes discovered JS URLs to a file for download."""
    if not crawled_urls_file or not crawled_urls_file.exists():
        return None
    out = out_dir / "03b_js_urls.txt"
    if dry_run:
        return out
    js_urls: set[str] = set()
    js_pattern = re.compile(r"""['"]([^'"]*\.js(?:\?[^'"]*)?)['"]""")

    # Scan crawled URLs file for inline JS references
    for line in crawled_urls_file.open(encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        for m in js_pattern.finditer(line):
            candidate = m.group(1)
            if candidate.startswith(("http://", "https://")):
                js_urls.add(candidate)
            elif candidate.startswith("//"):
                # Protocol-relative — prepend https:
                js_urls.add("https:" + candidate)

    # Also scan downloaded files (if available) for JS references
    if downloaded_dir and downloaded_dir.exists():
        for p in downloaded_dir.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in (".html", ".htm", ".js", ".mjs"):
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in js_pattern.finditer(content):
                candidate = m.group(1)
                if candidate.startswith(("http://", "https://")):
                    js_urls.add(candidate)
                elif candidate.startswith("//"):
                    js_urls.add("https:" + candidate)
                elif candidate.startswith("/"):
                    # Relative to host — extract base from downloaded file name
                    pass  # requires host context, skip for now

    if not js_urls:
        return None
    out.write_text("\n".join(sorted(js_urls)) + "\n", encoding="utf-8")
    print(color(f"[+] extracted {len(js_urls)} JS URL(s) from crawled content", GREEN))
    return out


def stage_syck(targets: Iterable[Path], out_dir: Path,
               severity: str = "LOW", fmt: str = "text",
               redact: bool = False, workers: int = 4,
               max_file_size: str = "5M",
               decode_base64: bool = True,
               decode_hex: bool = False,
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
    if not decode_base64:
        args.append("--no-decode-base64")
    if decode_hex:
        args.append("--decode-hex")
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
# Scope filtering
# ──────────────────────────────────────────────

def filter_scope(url_list: Path, pattern: str,
                 dry_run: bool = False) -> Path | None:
    """Filter URLs by a regex scope pattern."""
    compiled = re.compile(pattern)
    out = url_list.with_suffix(".scope.txt") if not dry_run else url_list
    if dry_run:
        return out
    total = 0
    kept = 0
    with out.open("w", encoding="utf-8") as dst:
        for line in url_list.open(encoding="utf-8", errors="replace"):
            total += 1
            if compiled.search(line.strip()):
                dst.write(line)
                kept += 1
    print(color(f"[*] scope filter: {kept}/{total} URL(s) match '{pattern}'", CYAN))
    if kept == 0:
        print(color("[!] scope filter eliminated all URLs", YELL))
        return None
    return out


# ──────────────────────────────────────────────
# Checkpoint / resume helpers
# ──────────────────────────────────────────────

def save_checkpoint(out_dir: Path, stage: str) -> None:
    """Write a checkpoint file noting the last completed stage."""
    cp = out_dir / CHECKPOINT_FILE
    cp.write_text(json.dumps({"stage": stage}, indent=2), encoding="utf-8")


def load_checkpoint(out_dir: Path) -> str | None:
    """Read the last completed stage from checkpoint. Returns None if no checkpoint."""
    cp = out_dir / CHECKPOINT_FILE
    if not cp.exists():
        return None
    try:
        data = json.loads(cp.read_text(encoding="utf-8"))
        return data.get("stage")
    except (json.JSONDecodeError, OSError):
        return None


def resume_from(stage: str, out_dir: Path,
                domains: list[str], args) -> str | None:
    """Determine which stage to resume from based on existing output files.

    Checks for each stage's output file. Returns the stage name (e.g. 'subfinder')
    to resume FROM (the next uncompleted stage), or None if everything is done.
    """
    stages = [
        ("subfinder", "01_subdomains.txt"),
        ("httpx",     "02_live_urls.txt"),
        ("wayback",   "03_wayback_urls.txt"),
        ("katana",    "03_urls.txt"),
        ("download",  "_downloaded_js"),
    ]
    last = stage
    for name, marker in stages:
        target = out_dir / marker
        if name == "download":
            if target.is_dir() and any(target.iterdir()):
                last = name
                continue
        elif target.exists() and target.stat().st_size > 0:
            last = name
            continue
        # Found first missing stage — resume from this point
        print(color(f"[*] resuming from stage '{name}' (previous checkpoint: '{stage}')", CYAN))
        return name
    return None
