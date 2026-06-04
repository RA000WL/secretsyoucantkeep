from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from syck.config import _load_config
from syck.formatters import FORMATTERS
from syck.rules import RULES, _RULE_RANK, SEVERITY_ORDER, load_custom_rules
from syck.scanner import (
    _downgrade_fp_findings, _fetch_url, deduplicate_findings,
    scan_file, scan_paths, scan_string,
)
from syck.ignore import filter_ignored, load_ignore_list
from syck.utils import (
    BOLD, CYAN, DEBUG, DEFAULT_MAX_FILE_SIZE, DEFAULT_WORKERS,
    GREEN, GREY, RED, USE_COLOR, YELLOW, color, debug, parse_size,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="syck",
        description=(
            "Scan files/folders for exposed secrets (bug bounty edition).\n"
            "\n"
            "By default detected secrets are printed IN FULL so you can paste them\n"
            "straight into a bug bounty report. Use --redact to mask them, and never\n"
            "share unredacted output on public trackers."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
WHAT IT FINDS (rule categories):
  Cloud ........... AWS, GCP, Azure, Oracle, DigitalOcean, Cloudflare, Vercel
  Source control .. GitHub (PAT/OAuth/App/Server/Fine-grained), GitLab, Bitbucket
  Messaging ....... Slack, Discord, Telegram, Twilio, Mailgun, SendGrid,
                   Mailchimp, Brevo
  Payments ........ Stripe, Square, PayPal
  AI providers .... OpenAI, Anthropic, HuggingFace, Replicate, Cohere, Groq,
                   Perplexity
  SaaS ............ Supabase, PlanetScale, Linear, ngrok, New Relic, Datadog,
                   Sentry, Pulumi, Dynatrace, Okta, Dropbox, Asana
  Infra ........... HashiCorp Vault, Docker Hub, Kubernetes Secrets, PyPI,
                   RubyGems, Terraform Cloud, SSH/SMTP/FTP passwords
  Crypto .......... RSA/DSA/EC/OpenSSH/PGP private keys, certificates
  Databases ....... Postgres, MySQL, MongoDB, Redis connection strings
  Generic ......... Bearer/Basic auth, JWT, "key=value" secrets, dotenv-style
  Catch-all ....... High-entropy token sweep (catches unknown patterns)

EXIT CODES:
  0  No secrets found (or --list-rules only)
  1  One or more secrets were found
  2  Invalid arguments / missing paths

BUG-BOUNTY TIPS:
  \x95  Run on a fresh target repo:    %(prog)s ./repo --severity CRITICAL
  \x95  Generate a clean report:        %(prog)s ./repo --format html -o r.html
  \x95  Upload to GitHub code scanning: %(prog)s ./repo --format sarif --redact \\
                                       -o results.sarif
  \x95  Scan JS/TS build artefacts:     %(prog)s ./dist --max-file-size 50M
  \x95  Skip noisy dirs:                %(prog)s ./repo --exclude 'test|mock|spec'
  \x95  CI gate (fail on CRITICAL only):
        %(prog)s . --severity CRITICAL || exit 1

EXAMPLES:
  %(prog)s .                              scan current folder, show secrets in full
  %(prog)s /path/to/repo --format html -o report.html
  %(prog)s . --format sarif -o report.sarif
  %(prog)s . --format markdown -o report.md
  %(prog)s . --severity HIGH              only HIGH and CRITICAL
  %(prog)s . --redact                     mask secrets in output
  %(prog)s . --workers 8 --max-file-size 5M
  %(prog)s . --exclude "test|mock"        skip paths matching regex
  %(prog)s file1.env file2.yaml           scan specific files
  %(prog)s https://example.com/app.bundle.js    scan a remote JS file
  %(prog)s . --list-rules                 list all built-in rules and exit
""",
    )
    p.add_argument("paths", nargs="*", default=["."],
                   help="Files, directories, or URLs to scan. "
                        "URLs (http://, https://) are downloaded to a "
                        "temp file, scanned, then deleted. "
                        "(default: current directory)")
    p.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                   default="LOW", help="Minimum severity to report (default: LOW)")
    p.add_argument("--format", choices=list(FORMATTERS.keys()),
                   default="text", help="Output format (default: text)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write output to FILE instead of stdout")
    p.add_argument("--redact", action="store_true",
                   help="Mask secret values in the output (default: shown in full)")
    p.add_argument("--show-secrets", action="store_true",
                   help=argparse.SUPPRESS)
    p.add_argument("--no-entropy", action="store_true",
                   help="Disable high-entropy token sweep")
    p.add_argument("--decode-base64", action="store_true",
                   default=True,
                   help=argparse.SUPPRESS)
    p.add_argument("--no-decode-base64", action="store_false",
                   dest="decode_base64",
                   help="Disable base64 decode and re-scan of found strings")
    p.add_argument("--decode-hex", action="store_true",
                   default=False,
                   help="Decode hex-encoded strings and re-scan for secrets")
    p.add_argument("--no-decode-hex", action="store_false",
                   dest="decode_hex",
                   help="Disable hex decode and re-scan")
    p.add_argument("--follow-symlinks", action="store_true",
                   help="Follow symlinks")
    p.add_argument("--no-skip-binary", action="store_true",
                   help="Attempt to scan binary files")
    p.add_argument("--exclude", metavar="REGEX", action="append", default=[],
                   help="Exclude paths matching this regex (repeatable)")
    p.add_argument("--exclude-file", metavar="FILE",
                   help="Read exclude patterns from a file (one regex per line, "
                        "# comments and blank lines ignored)")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS, metavar="N",
                   help=f"Parallel workers for file scanning (default: {DEFAULT_WORKERS})")
    p.add_argument("--max-file-size", type=parse_size,
                   default=DEFAULT_MAX_FILE_SIZE, metavar="BYTES",
                   help="Skip files larger than this. Accepts K/M/G suffix "
                        f"(default: {DEFAULT_MAX_FILE_SIZE // (1024 * 1024)}M)")
    p.add_argument("--rules", metavar="FILE",
                   help="Load additional detection rules from a JSON file")
    p.add_argument("--rules-only", action="store_true",
                   help="Skip built-in rules (requires --rules)")
    p.add_argument("--no-color", action="store_true",
                   help="Disable colored output")
    p.add_argument("--debug", action="store_true",
                   help="Enable verbose debug logging")
    p.add_argument("--config", metavar="FILE",
                   help="Path to config file (default: ./.syckrc, "
                        "~/.config/syck/config.json)")
    p.add_argument("--progress", action="store_true",
                   help="Print a one-line progress message to stderr")
    p.add_argument("--no-dedup", action="store_true",
                   help="Show all findings including duplicates across files")
    p.add_argument("--ignore-file", metavar="FILE",
                   help="Path to ignore file (default: ./.syckignore)")
    p.add_argument("--add-ignore", metavar="FINGERPRINT",
                   help="Add a finding fingerprint to .syckignore and exit")
    p.add_argument("--endpoints", action="store_true",
                   help="Also extract API endpoints and URLs from source files")
    p.add_argument("--git-history", action="store_true",
                   help="Also scan git commit history for secrets in deleted files "
                        "(requires git in PATH, run from inside a repo)")
    p.add_argument("--pipe", action="store_true",
                   help="Read content from stdin and scan it in-memory")
    p.add_argument("--validate", action="store_true",
                   help="Verify found secrets against provider APIs (zero-dependency)")
    p.add_argument("--list-rules", action="store_true",
                   help="Print all built-in rules and exit")
    p.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   default=None, metavar="SEVERITY",
                   help="Exit code 1 if any finding at or above this severity "
                        "(useful for CI gates; default: any finding exits 1)")
    per_group = p.add_argument_group("performance")
    per_group.add_argument("--no-cache", action="store_true",
                           help="Disable the .syck-cache (default: auto)")
    per_group.add_argument("--cache-dir", metavar="DIR",
                           help="Cache directory (default: ./.syck-cache)")
    ci_group = p.add_argument_group("CI/CD")
    ci_group.add_argument("--upload-sarif", action="store_true",
                          help="Upload SARIF results to GitHub Code Scanning")
    ci_group.add_argument("--github-repo", metavar="owner/repo",
                          help="GitHub repo for SARIF upload (auto-detected from git remote)")
    ci_group.add_argument("--github-token", metavar="TOKEN",
                          help="GitHub token for SARIF upload (default: $GITHUB_TOKEN)")
    webhook_group = p.add_argument_group("webhooks")
    webhook_group.add_argument("--webhook-url", metavar="URL", action="append", default=[],
                               help="POST findings to this URL (repeatable)")
    webhook_group.add_argument("--webhook-format", choices=["slack", "discord", "json"],
                               default="json", help="Webhook payload format (default: json)")
    recon_group = p.add_argument_group("advanced detection")
    recon_group.add_argument("--decode-gzip", action="store_true", default=False,
                             help="Decompress gzip/zlib content and re-scan")
    recon_group.add_argument("--decode-unicode", action="store_true", default=False,
                             help="Decode \\\\uXXXX unicode escape sequences and re-scan")
    recon_group.add_argument("--js-reconstruct", action="store_true", default=False,
                             help="Reconstruct JS string concatenations, array joins, and template literals")
    return p


def main(argv: list[str]) -> int:
    global USE_COLOR, DEBUG

    parser = build_parser()

    known, _ = parser.parse_known_args(argv)

    cfg = _load_config(known)
    if cfg:
        parser.set_defaults(**cfg)

    args = parser.parse_args(argv)

    if args.no_color or args.format != "text":
        USE_COLOR = False

    if args.debug:
        DEBUG = True
        debug("debug logging enabled")

    if cfg:
        debug(f"loaded config with {len(cfg)} key(s): {list(cfg.keys())}")

    cache: object = None
    if not args.no_cache:
        try:
            from syck_cache import SyckCache
            cache_dir = Path(args.cache_dir) if args.cache_dir else Path(".syck-cache")
            cache = SyckCache(cache_dir)
            debug(f"cache initialized at {cache_dir}")
        except Exception:
            pass

    if args.rules:
        debug(f"loading custom rules from {args.rules}")
        custom_rules = load_custom_rules(args.rules)
        if args.rules_only:
            RULES.clear()
            _RULE_RANK.clear()
        RULES.extend(custom_rules)
        for r in custom_rules:
            _RULE_RANK[r.name] = SEVERITY_ORDER[r.severity]
        debug(f"loaded {len(custom_rules)} custom rule(s), total rules: {len(RULES)}")

    if args.list_rules:
        print(f"{'Rule':<35} {'Severity':<10} Pattern")
        print("-" * 90)
        for rule in RULES:
            print(f"{rule.name:<35} {rule.severity:<10} {rule.pattern.pattern[:45]}")
        if args.rules_only:
            print("\n(Built-in rules excluded via --rules-only)")
        return 0

    if args.pipe:
        content = sys.stdin.read()
        source = "<stdin>"
        if args.paths and args.paths != ["."]:
            source = args.paths[0]
        findings = scan_string(
            content=content,
            source=source,
            min_severity=args.severity,
            high_entropy_scan=not args.no_entropy,
            decode_base64=args.decode_base64,
            decode_hex=args.decode_hex,
            extract_endpoints_flag=args.endpoints,
            decode_gzip=args.decode_gzip,
            decode_unicode=args.decode_unicode,
            js_reconstruct=args.js_reconstruct,
        )
        if not args.no_dedup:
            findings = deduplicate_findings(findings)
        findings = _downgrade_fp_findings(findings)
        ignore = load_ignore_list(Path(args.ignore_file) if args.ignore_file else None)
        if ignore:
            findings = filter_ignored(findings, ignore)
        formatter = FORMATTERS[args.format]
        output_text = formatter(findings, args.redact)
        if args.output:
            out_path = Path(args.output)
            out_path.write_text(output_text, encoding="utf-8")
        else:
            print(output_text, end="")
        if args.fail_on:
            threshold = SEVERITY_ORDER[args.fail_on]
            for f in findings:
                if SEVERITY_ORDER.get(f.severity, 99) <= threshold:
                    return 1
            return 0
        return 1 if findings else 0

    local_paths = [p for p in args.paths if not p.startswith(("http://", "https://"))]
    urls = [p for p in args.paths if p.startswith(("http://", "https://"))]

    targets = [Path(p).resolve() for p in local_paths]
    missing = [t for t in targets if not t.exists()]
    if missing:
        for m in missing:
            print(color(f"error: path does not exist: {m}", RED), file=sys.stderr)
        return 2

    temp_dir: Path | None = None
    if urls:
        temp_dir = Path(tempfile.mkdtemp(prefix="syck-urls-"))
        print(color(f"[*] fetching {len(urls)} URL(s) into {temp_dir}",
                    GREY), file=sys.stderr)
        async_fetched = 0
        try:
            from syck.async_fetch import fetch_urls_async
            fetched = fetch_urls_async(urls, temp_dir)
            targets.extend(fetched)
            async_fetched = len(fetched)
            debug(f"async fetcher retrieved {async_fetched}/{len(urls)} URL(s)")
        except ImportError:
            debug("syck_async not available, using threaded fallback")
        if async_fetched < len(urls):
            for u in urls:
                fetched = _fetch_url(u, temp_dir)
                if fetched is not None:
                    targets.append(fetched)

    try:
        if args.exclude_file:
            try:
                with open(args.exclude_file) as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            args.exclude.append(line)
            except OSError as e:
                print(color(f"[!] failed to read --exclude-file: {e}", RED), file=sys.stderr)
                return 2

        exclude_patterns = [re.compile(pat) for pat in args.exclude] if args.exclude else None
        redact_secrets = args.redact or bool(args.show_secrets)

        findings = scan_paths(
            targets=targets,
            skip_binary=not args.no_skip_binary,
            follow_symlinks=args.follow_symlinks,
            min_severity=args.severity,
            high_entropy_scan=not args.no_entropy,
            decode_base64=args.decode_base64,
            decode_hex=args.decode_hex,
            exclude_patterns=exclude_patterns,
            workers=max(1, args.workers),
            max_file_size=args.max_file_size,
            progress=args.progress,
            extract_endpoints_flag=args.endpoints,
            cache=cache,
            decode_gzip=args.decode_gzip,
            decode_unicode=args.decode_unicode,
            js_reconstruct=args.js_reconstruct,
        )
        debug(f"scan_paths returned {len(findings)} finding(s)")
    finally:
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)

    if args.git_history:
        from syck.git_scanner import scan_git_history
        for target in targets:
            if (target / ".git").exists() or target.name == ".git":
                repo = target if (target / ".git").exists() else target.parent
                print(color(f"[*] scanning git history of {repo}…", GREY), file=sys.stderr)
                findings.extend(scan_git_history(repo, args.severity, max(1, args.workers)))

    findings = _downgrade_fp_findings(findings)

    if not args.no_dedup:
        findings = deduplicate_findings(findings)

    if args.add_ignore:
        ignore_path = Path(args.ignore_file) if args.ignore_file else Path(".syckignore")
        fingerprint = args.add_ignore.strip()
        with ignore_path.open("a", encoding="utf-8") as f:
            f.write(fingerprint + "\n")
        print(color(f"[+] added {fingerprint} to {ignore_path}", GREEN))
        return 0

    ignore = load_ignore_list(Path(args.ignore_file) if args.ignore_file else None)
    if ignore:
        findings = filter_ignored(findings, ignore)

    if args.validate and findings:
        try:
            from syck_validate import validate_findings
            print(color("[*] validating secrets against provider APIs…", CYAN), file=sys.stderr)
            validation = validate_findings(findings)
            for (rule, secret_prefix), result in validation.items():
                icon = color("[LIVE]", RED + BOLD) if result.valid else color("[DEAD]", GREY)
                print(f"  {icon} {rule}: {result.detail}", file=sys.stderr)
        except ImportError:
            print(color("[!] syck_validate.py not found (expected alongside syck.py)", YELLOW),
                  file=sys.stderr)

    if args.webhook_url and findings:
        try:
            from syck_webhook import send_webhooks
            for url in args.webhook_url:
                send_webhooks(url, findings, args.webhook_format, redact_secrets)
        except ImportError:
            print(color("[!] syck_webhook.py not found", YELLOW), file=sys.stderr)

    formatter = FORMATTERS[args.format]
    output_text = formatter(findings, redact_secrets)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(output_text, encoding="utf-8")
        if USE_COLOR:
            print(color(f"Results written to {out_path}", GREEN))
    else:
        print(output_text, end="")

    if args.upload_sarif and args.format == "sarif" and args.output:
        try:
            from syck_sarif import upload_sarif
            token = args.github_token or os.environ.get("GITHUB_TOKEN", "")
            repo = args.github_repo or ""
            if not repo:
                try:
                    import subprocess
                    remote = subprocess.run(
                        ["git", "remote", "get-url", "origin"],
                        capture_output=True, text=True, timeout=5
                    ).stdout.strip()
                    for prefix in ("https://github.com/", "git@github.com:"):
                        if remote.startswith(prefix):
                            repo = remote.removeprefix(prefix).removesuffix(".git")
                            break
                except Exception:
                    pass
            if repo and token:
                upload_sarif(args.output, repo, token)
            elif repo:
                print(color("[!] GITHUB_TOKEN not set, skipping SARIF upload", YELLOW),
                      file=sys.stderr)
        except ImportError:
            print(color("[!] syck_sarif.py not found", YELLOW), file=sys.stderr)

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        for f in findings:
            if SEVERITY_ORDER.get(f.severity, 99) <= threshold:
                return 1
        return 0
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
