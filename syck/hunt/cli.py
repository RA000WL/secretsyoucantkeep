"""syck.hunt.cli — argparse + main() entry point for the syck-hunt pipeline."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from syck.hunt import utils
from syck.hunt.recon import _stream_js, stage_deep_js, stage_extract_source_maps, stage_gau
from syck.hunt.stages import (
    filter_scope, load_checkpoint, resume_from, save_checkpoint,
    stage_async_download, stage_download, stage_extract_js_urls,
    stage_httpx, stage_katana, stage_probe, stage_subfinder, stage_syck,
)
from syck.hunt.utils import (
    BANNER, BOLD, CYAN, GREEN, GREY, RED, YELL,
    check_tools, color, hr, which,
)

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
  -hl  --headless            -sm  --extract-source-maps      -xs  --extract-scripts
  --no-decode-base64               --header NAME:VALUE      --cookie COOKIE

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
    stages.add_argument("-pc", "--probe-crawled", action="store_true",
                        help="Probe crawled URLs with httpx -mc 200 before "
                             "download (filters out dead URLs, making the "
                             "file cap go further)")
    stages.add_argument("-ad", "--async-download", action="store_true",
                        help="Use aiohttp + SQLite content cache for async "
                             "URL download (install aiohttp for best perf)")
    stages.add_argument("-ej", "--extract-js-urls", action="store_true",
                        help="Extract additional JS URLs from crawled content "
                             "using regex patterns")

    crawl = ap.add_argument_group("crawl tuning")
    crawl.add_argument("-d", "--depth", type=int, default=2,
                       help="Katana crawl depth (default: 2)")
    crawl.add_argument("-hl", "--headless", action="store_true",
                       help="Use katana's headless browser for JS-rendered "
                            "links (discovers SPA routes like /#/score-board)")
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
    scan.add_argument("--decode-base64", action="store_true", default=True,
                      help=argparse.SUPPRESS)  # backward compat
    scan.add_argument("--no-decode-base64", action="store_false",
                      dest="decode_base64",
                      help="Disable base64 decode and re-scan")
    scan.add_argument("-w", "--workers", type=int, default=4,
                      dest="syck_workers",
                      help="syck --workers (default: 4)")
    scan.add_argument("-sp", "--syck-path", metavar="PATH",
                      help="Path to syck.py (or 'syck' binary). "
                           "Use this if syck isn't on $PATH.")
    scan.add_argument("-sm", "--extract-source-maps", action="store_true",
                      help="Extract original sources from source maps "
                           "and scan them for secrets")
    scan.add_argument("-sj", "--stream-js", action="store_true",
                       help="Stream JS files in memory and scan with syck --pipe, "
                            "bypassing disk for downloaded files")
    scan.add_argument("-dj", "--deep-js", action="store_true",
                       help="Deep JS recon: extract endpoints, API routes, "
                            "variables, hidden subdomains, tokens, and more "
                            "from every JS file (generates deep_js_report.json)")

    misc = ap.add_argument_group("misc")
    misc.add_argument("-ct", "--check-tools", action="store_true",
                      help="Check which dependencies are present and exit")
    misc.add_argument("-dr", "--dry-run", action="store_true",
                      help="Print commands without executing them")
    misc.add_argument("-nc", "--no-color", action="store_true",
                      help="Disable coloured output")
    misc.add_argument("--wayback", action="store_true",
                      help="Use Wayback Machine URLs (via gau/waybackurls) "
                           "instead of katana crawling")
    misc.add_argument("--scope", metavar="REGEX",
                      help="Filter discovered URLs by regex scope "
                           "(e.g. 'example\\.com|api\\.example\\.com'). "
                           "Applies after URL discovery, before download.")
    misc.add_argument("--resume", action="store_true",
                      help="Resume from last checkpoint. Skips completed "
                           "stages automatically.")
    misc.add_argument("--decode-hex", action="store_true",
                      help="Decode hex-encoded strings and rescan for secrets")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.no_color:
        utils.USE_COLOR = False

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
            decode_base64=args.decode_base64,
            decode_hex=args.decode_hex,
            syck_cmd=syck_cmd,
            dry_run=args.dry_run,
        )
        if args.deep_js and not args.dry_run:
            target_path = Path(args.scan_only)
            if target_path.is_file():
                files_dir = target_path.parent
            else:
                files_dir = target_path
            deep_js_report = stage_deep_js(files_dir, out_dir)
        ret = _summarise(out_dir, report, args.dry_run)
        if deep_js_report:
            print(color(f"[✓] deep JS report: {deep_js_report}", CYAN))
        return ret

    # Diagnostic: show effective rate limit
    rl = args.rate_limit
    if rl > 0:
        katana_rl = f"{round(1.0/rl)}s" if rl < 1 else "unlimited"
        print(color(f"[*] rate limit: {rl} req/s "
                    f"(httpx: {int(1000/rl)}ms, katana: {katana_rl}, "
                    f"downloader: {1000/rl:.0f}ms)", CYAN))
    else:
        print(color("[*] rate limit: unlimited", CYAN))

    # Mode 2: full recon → download → syck

    # Checkpoint resume
    force_stage: str | None = None
    if args.resume:
        stage = load_checkpoint(out_dir)
        if stage:
            print(color(f"[*] found checkpoint: last completed stage '{stage}'", CYAN))
            force_stage = resume_from(stage, out_dir, domains, args)
            if force_stage is None:
                print(color("[*] all stages already complete, re-running syck", CYAN))
                force_stage = "syck"
        else:
            print(color("[*] no checkpoint found, starting from scratch", CYAN))
            save_checkpoint(out_dir, "start")

    if args.enum_subs:
        if force_stage and force_stage != "subfinder":
            print(color(f"[*] skipping subfinder (resuming from '{force_stage}')", CYAN))
            subs = out_dir / "01_subdomains.txt"
        else:
            print(color(f"[*] -es: enumerating subdomains for {len(domains)} "
                        f"target domain(s) with subfinder", CYAN))
            subs = stage_subfinder(domains, out_dir, dry_run=args.dry_run)
            if subs:
                save_checkpoint(out_dir, "subfinder")
    else:
        # Default: skip subdomain enumeration.  Write the input domains
        # straight to a file in subfinder's slot — stage_httpx doesn't
        # care where the host list came from.
        if force_stage and force_stage not in ("subfinder", "httpx"):
            subs = out_dir / "01_subdomains.txt" if (out_dir / "01_subdomains.txt").exists() else out_dir / "00_targets.txt"
        else:
            subs = out_dir / "00_targets.txt"
            if not args.dry_run:
                subs.write_text("\n".join(domains) + "\n", encoding="utf-8")
                save_checkpoint(out_dir, "subfinder")
    if not subs and not args.dry_run:
        return _summarise(out_dir, None, args.dry_run)

    # httpx stage
    if force_stage and force_stage not in ("subfinder", "httpx"):
        hosts = out_dir / "02_live_urls.txt"
        if not hosts.exists() or hosts.stat().st_size == 0:
            hosts = subs if subs.exists() else None
    else:
        hosts = stage_httpx(subs, out_dir,
                            rate_limit=args.rate_limit,
                            dry_run=args.dry_run)
        if hosts:
            save_checkpoint(out_dir, "httpx")
    if not hosts and not args.dry_run:
        return _summarise(out_dir, None, args.dry_run)

    if args.no_katana and not args.wayback:
        return _summarise(out_dir, None, args.dry_run)

    # Wayback mode (uses gau/waybackurls instead of katana)
    if args.wayback:
        if force_stage and force_stage not in ("subfinder", "httpx", "wayback"):
            urls = out_dir / "03_wayback_urls.txt"
            if not urls.exists() or urls.stat().st_size == 0:
                print(color("[!] Wayback URLs missing, re-fetching", YELL))
                urls = stage_gau(domains, out_dir, rate_limit=args.rate_limit, dry_run=args.dry_run)
        else:
            urls = stage_gau(domains, out_dir, rate_limit=args.rate_limit, dry_run=args.dry_run)
            if urls:
                save_checkpoint(out_dir, "wayback")
        if not urls and not args.dry_run:
            return _summarise(out_dir, None, args.dry_run)
    else:
        if force_stage and force_stage not in ("subfinder", "httpx", "wayback", "katana"):
            urls = out_dir / "03_urls.txt"
            if not urls.exists() or urls.stat().st_size == 0:
                print(color("[!] crawled URLs missing, re-crawling", YELL))
                urls = stage_katana(hosts, out_dir,
                                    depth=args.depth,
                                    rate_limit=args.rate_limit,
                                    concurrency=args.katana_conc,
                                    headless=args.headless,
                                    dry_run=args.dry_run)
        else:
            urls = stage_katana(hosts, out_dir,
                                depth=args.depth,
                                rate_limit=args.rate_limit,
                                concurrency=args.katana_conc,
                                headless=args.headless,
                                dry_run=args.dry_run)
            if urls:
                save_checkpoint(out_dir, "katana")
        if not urls and not args.dry_run:
            return _summarise(out_dir, None, args.dry_run)

    # Scope filtering: filter discovered URLs before download
    if args.scope and urls:
        scoped = filter_scope(urls, args.scope, dry_run=args.dry_run)
        if scoped and scoped.exists() and scoped.stat().st_size > 0:
            urls = scoped
        elif not args.dry_run:
            print(color("[!] scope filter removed all URLs, aborting", RED))
            return _summarise(out_dir, None, args.dry_run)

    # --extract-js-urls: find additional JS URLs in crawled content
    if args.extract_js_urls and urls and urls.exists():
        js_urls = stage_extract_js_urls(urls, out_dir, dry_run=args.dry_run)
        if js_urls and js_urls.exists():
            existing: set[str] = set()
            for line in urls.open(encoding="utf-8", errors="replace"):
                u = line.strip()
                if u and u.startswith(("http://", "https://")):
                    existing.add(u)
            for line in js_urls.open(encoding="utf-8", errors="replace"):
                u = line.strip()
                if u and u.startswith(("http://", "https://")):
                    existing.add(u)
            merged = out_dir / "03c_merged_urls.txt"
            merged.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")
            print(color(f"[+] merged {len(existing)} total URL(s) after JS extraction", GREEN))
            urls = merged

    # --probe-crawled: filter URLs to 200 OK before download
    effective_max = args.max_files
    if args.probe_crawled and urls and not args.no_download:
        probed = stage_probe(urls, out_dir,
                             rate_limit=args.rate_limit,
                             dry_run=args.dry_run)
        if probed:
            urls = probed
            # Increase effective cap since all URLs are verified alive
            if args.max_files == 200:
                effective_max = args.max_files * 2
        elif not args.dry_run:
            print(color("[!] probe-crawled found no live URLs, aborting", RED))
            return _summarise(out_dir, None, args.dry_run)

    if args.no_download:
        print(color("\n[✓] recon complete (download skipped)", GREEN))
        return _summarise(out_dir, None, args.dry_run)

    # --stream-js: in-memory fetch + pipe to syck, bypassing disk
    if args.stream_js:
        syck_cmd = _resolve_syck(args, interactive=not args.dry_run)
        if syck_cmd is None:
            return _summarise(out_dir, None, args.dry_run)
        report = _stream_js(
            urls, out_dir, syck_cmd,
            workers=args.download_workers,
            rate_limit=args.rate_limit,
            max_per_host=args.max_concurrent,
            extra_headers=extra_headers or None,
            dry_run=args.dry_run,
        )
        return _summarise(out_dir, report, args.dry_run)

    # --async-download: aiohttp + SQLite cache pipeline
    if args.async_download:
        files = stage_async_download(
            urls, out_dir,
            max_files=effective_max,
            workers=args.download_workers,
            js_only=args.js_only,
            filter_content_type=bool(args.probe_crawled),
            extra_headers=extra_headers or None,
            dry_run=args.dry_run,
        )

    files = stage_download(
        urls, out_dir,
        max_files=effective_max,
        workers=args.download_workers,
        js_only=args.js_only,
        rate_limit=args.rate_limit,
        max_per_host=args.max_concurrent,
        js_depth=args.js_depth,
        extract_scripts=args.extract_scripts,
        extra_headers=extra_headers or None,
        filter_content_type=bool(args.probe_crawled),
        dry_run=args.dry_run,
    )
    if not files and not args.dry_run:
        return _summarise(out_dir, None, args.dry_run)
    if files:
        save_checkpoint(out_dir, "download")

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

    # Optional: deep JS recon
    deep_js_report: Path | None = None
    if args.deep_js and files:
        deep_js_report = stage_deep_js(files, out_dir, dry_run=args.dry_run)

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
        decode_base64=args.decode_base64,
        decode_hex=args.decode_hex,
        syck_cmd=syck_cmd,
        dry_run=args.dry_run,
    )
    save_checkpoint(out_dir, "syck")
    ret = _summarise(out_dir, report, args.dry_run)
    if deep_js_report:
        print(color(f"[✓] deep JS report: {deep_js_report}", CYAN))
    return ret


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
      1. ``--syck-path`` (explicit)
      2. ``syck`` on $PATH
      3. ``syck.py`` next to this script (auto-discovery)
      4. Friendly hint + ``None``
    """
    # 1. Explicit --syck-path
    if args.syck_path:
        p = Path(args.syck_path)
        if not p.exists():
            print(color(f"[!] --syck-path {p} does not exist", RED),
                  file=sys.stderr)
            return None
        if p.suffix == ".py":
            return [sys.executable, str(p)]
        return [str(p)]

    # 2. On PATH
    if which("syck"):
        return ["syck"]

    # 3. Auto-discover syck.py next to this script
    script_dir = Path(__file__).parent.resolve()
    local_syck = script_dir / "syck.py"
    if local_syck.exists():
        if interactive and utils.USE_COLOR:
            print(color(f"[*] discovered syck at {local_syck}", CYAN), file=sys.stderr)
        return [sys.executable, str(local_syck)]

    # 4. Give up with a hint
    if interactive:
        print(color("\n[!] 'syck' not found on $PATH and syck.py not found next "
                    "to this script.", YELL))
        print(color("    To fix:", YELL))
        print(color("      a) Symlink:     ln -s /path/to/syck.py ~/bin/syck", YELL))
        print(color("      b) Use --syck-path /path/to/syck.py", YELL))
        print(color("      c) Keep the scripts together in the same directory", YELL))
    return None
