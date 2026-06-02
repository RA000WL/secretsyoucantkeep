#!/usr/bin/env python3
"""
syck-hunt.py — bug-bounty recon → secrets pipeline orchestrator.

Wires together the ProjectDiscovery toolchain into the secrets scanner:

    subfinder  →  httpx  →  katana  →  download JS  →  syck

Each stage writes its output to the run directory so you can inspect or
re-run individual stages manually.

Usage:
  syck-hunt example.com
  syck-hunt example.com --js-only
  syck-hunt example.com --no-download
  syck-hunt -l domains.txt --output-dir ./recon
  syck-hunt --scan-only ./repo --severity CRITICAL
  syck-hunt --check-tools
  syck-hunt example.com --dry-run
"""
from __future__ import annotations

import argparse
import concurrent.futures
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
 syck-hunt — recon → secrets pipeline
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


def check_tools(skip_katana: bool = False) -> bool:
    """Print which tools are present and warn about anything missing."""
    required = ["subfinder", "httpx", "syck"]
    if not skip_katana:
        required.append("katana")
    print(color("Tool check:", BOLD))
    ok = True
    for t in required:
        path = which(t)
        if path:
            print(color(f"  [✓] {t:<11} {path}", GREEN))
        else:
            print(color(f"  [✗] {t:<11} not found in PATH", RED))
            ok = False
    if not ok:
        print(color("\nInstall missing tools:", YELL))
        for t, url in TOOL_URLS.items():
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
    if dry_run:
        return raw
    if rc != 0 or not raw.exists() or raw.stat().st_size == 0:
        print(color("[!] httpx found no live hosts", YELL))
        return None
    # httpx-with-flags output is "<url> [<code>] [<title>]"; keep just URLs
    urls = out_dir / "02_live_urls.txt"
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
    if rate_limit > 0:
        # katana: -rate-limit is in seconds between requests
        args += ["-rate-limit", str(round(1.0 / rate_limit, 3))]
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
                  timeout: int = 20) -> Path | None:
    name = _safe_name(url)
    dest = dest_dir / name
    i = 1
    while dest.exists():
        stem, suf = dest.stem, dest.suffix
        dest = dest_dir / f"{stem}_{i}{suf}"
        i += 1
    host = urlparse(url).netloc or "unknown"
    host_limiter.acquire(host)
    try:
        limiter.wait()
        req = urllib.request.Request(url, headers={"User-Agent": "syck-hunt/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            if not data:
                return None
            dest.write_bytes(data)
            return dest
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return None
    finally:
        host_limiter.release(host)


def stage_download(urls_file: Path, out_dir: Path, max_files: int = 200,
                   workers: int = 10, js_only: bool = True,
                   rate_limit: float = 5.0, max_per_host: int = 2,
                   dry_run: bool = False) -> Path | None:
    """Stage 4: download JS files for offline scanning."""
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
    urls = urls[:max_files]

    if dry_run:
        rps = f"{rate_limit} req/s" if rate_limit > 0 else "unlimited"
        print(color(
            f"DRY: would download {len(urls)} URL(s) → {files_dir} "
            f"({workers} workers, {rps}, ≤{max_per_host}/host)",
            GREY,
        ))
        return files_dir
    if not urls:
        print(color("[!] no URLs matched the filter", YELL))
        return None

    rps = f"{rate_limit} req/s" if rate_limit > 0 else "unlimited"
    print(color(
        f"[*] downloading {len(urls)} URL(s) — {workers} workers, {rps}, "
        f"≤{max_per_host}/host…", CYAN,
    ))
    limiter = RateLimiter(rate_limit)
    host_limiter = HostLimiter(max_per_host)
    ok = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
        futs = [exe.submit(_download_one, u, files_dir, limiter, host_limiter)
                for u in urls]
        for fut in concurrent.futures.as_completed(futs):
            if fut.result() is not None:
                ok += 1
    print(color(f"[+] {ok}/{len(urls)} downloaded", GREEN))
    return files_dir if ok > 0 else None


def stage_syck(targets: Iterable[Path], out_dir: Path,
               severity: str = "LOW", fmt: str = "html",
               redact: bool = False, workers: int = 4,
               max_file_size: str = "5M", dry_run: bool = False) -> Path | None:
    """Stage 5: scan downloaded files with syck."""
    targets = [t for t in targets if t is not None]
    if not targets:
        return None
    ext = "html" if fmt == "html" else fmt
    out = out_dir / f"04_syck_report.{ext}"
    args = ["syck", *[str(t) for t in targets],
            "--format", fmt, "-o", str(out),
            "--severity", severity,
            "--workers", str(workers),
            "--max-file-size", max_file_size]
    if redact:
        args.append("--redact")
    if dry_run:
        print(color(f"DRY: {' '.join(args)}", GREY))
        return out
    rc = run_cmd(args, dry_run)
    if rc not in (0, 1) or not out.exists():
        print(color("[!] syck did not produce a report", YELL))
        return None
    print(color(f"[+] report → {out}", GREEN))
    return out


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="syck-hunt",
        description="Recon → secrets pipeline (subfinder → httpx → katana → syck).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  syck-hunt example.com
  syck-hunt example.com --js-only
  syck-hunt example.com --no-download            # recon only, no scan
  syck-hunt -l domains.txt --output-dir ./recon
  syck-hunt --scan-only ./leaked-repo --severity CRITICAL
  syck-hunt --check-tools
  syck-hunt example.com --dry-run                # print commands, run nothing
""",
    )
    ap.add_argument("domains", nargs="*", help="Target domain(s)")
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="File with one domain per line")
    ap.add_argument("--output-dir", default="./recon",
                    help="Root output directory (default: ./recon)")
    ap.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    default="LOW", help="Minimum syck severity (default: LOW)")
    ap.add_argument("--format", choices=["text", "json", "sarif", "markdown",
                                          "csv", "html"], default="html",
                    help="syck report format (default: html)")

    recon = ap.add_argument_group("recon stages")
    recon.add_argument("--no-katana", action="store_true",
                       help="Skip katana crawling (stops after httpx)")
    recon.add_argument("--no-download", action="store_true",
                       help="Skip JS download (crawl-only mode)")
    recon.add_argument("--js-only", action="store_true", default=True,
                       help="Download only .js files (default: on)")
    recon.add_argument("--no-js-only", dest="js_only", action="store_false",
                       help="Download all crawled URLs, not just .js")
    recon.add_argument("--depth", type=int, default=2,
                       help="Katana crawl depth (default: 2)")
    recon.add_argument("--max-files", type=int, default=200,
                       help="Max files to download per run (default: 200)")
    recon.add_argument("--download-workers", type=int, default=10,
                       help="Concurrent download workers (default: 10)")
    recon.add_argument("--max-file-size", default="5M",
                       help="Max size per scanned file (default: 5M)")

    rate = ap.add_argument_group("rate limiting (be nice to the target)")
    rate.add_argument("--rate-limit", type=float, default=5.0, metavar="RPS",
                      help="Max requests per second across all stages "
                           "(default: 5, 0 to disable)")
    rate.add_argument("--max-concurrent-per-host", type=int, default=2,
                      metavar="N", help="Max simultaneous requests to one host "
                                        "(default: 2)")
    rate.add_argument("--katana-concurrency", type=int, default=10,
                      metavar="N", help="katana -concurrency (default: 10)")

    scan = ap.add_argument_group("scanning")
    scan.add_argument("--scan-only", metavar="PATH",
                      help="Skip recon, run syck directly on PATH (file or dir)")
    scan.add_argument("--syck-workers", type=int, default=4,
                      help="syck --workers (default: 4)")
    scan.add_argument("--redact", action="store_true",
                      help="Mask secrets in the report (default: shown in full)")

    misc = ap.add_argument_group("misc")
    misc.add_argument("--check-tools", action="store_true",
                      help="Check which dependencies are present and exit")
    misc.add_argument("--dry-run", action="store_true",
                      help="Print the commands without executing them")
    misc.add_argument("--no-color", action="store_true",
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
        return 0 if check_tools() else 1

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
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output_dir) / target_label / ts
    out_dir.mkdir(parents=True, exist_ok=True)
    print(color(f"[*] run directory: {out_dir}", CYAN))

    if not check_tools(skip_katana=args.no_katana or args.scan_only is not None):
        if not args.dry_run:
            return 1

    # Mode 1: scan-only
    if args.scan_only:
        report = stage_syck(
            targets=[Path(args.scan_only)],
            out_dir=out_dir,
            severity=args.severity,
            fmt=args.format,
            redact=args.redact,
            workers=args.syck_workers,
            max_file_size=args.max_file_size,
            dry_run=args.dry_run,
        )
        return _summarise(out_dir, report, args.dry_run)

    # Mode 2: full recon → download → syck
    subs = stage_subfinder(domains, out_dir, dry_run=args.dry_run)
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
                        concurrency=args.katana_concurrency,
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
        max_per_host=args.max_concurrent_per_host,
        dry_run=args.dry_run,
    )
    if not files and not args.dry_run:
        return _summarise(out_dir, None, args.dry_run)

    report = stage_syck(
        targets=[files] if files else [out_dir],
        out_dir=out_dir,
        severity=args.severity,
        fmt=args.format,
        redact=args.redact,
        workers=args.syck_workers,
        max_file_size=args.max_file_size,
        dry_run=args.dry_run,
    )
    return _summarise(out_dir, report, args.dry_run)


def _summarise(out_dir: Path, report: Path | None, dry_run: bool) -> int:
    print(color("\n" + hr("═"), BOLD))
    print(color(" Pipeline summary", BOLD))
    print(color(hr("═"), BOLD))
    for f in sorted(out_dir.iterdir()):
        if f.is_file():
            size = f.stat().st_size
            print(f"  {f.relative_to(out_dir):<30}  {size:>8} bytes")
        elif f.is_dir():
            count = sum(1 for _ in f.rglob("*") if _.is_file())
            print(f"  {f.relative_to(out_dir)}/  ({count} file(s))")
    if report:
        print(color(f"\n[✓] final report: {report}", GREEN))
    elif not dry_run:
        print(color("\n[i] recon complete, no scan run", YELL))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
