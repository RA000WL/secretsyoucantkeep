#!/usr/bin/env python3
"""
secretsyoucantkeep.py — local secrets scanner for bug bounty hunters.
Scans files and folders for exposed credentials, tokens, and keys.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

# ──────────────────────────────────────────────
# ANSI color codes (disabled with --no-color)
# ──────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
GREY    = "\033[90m"
MAGENTA = "\033[95m"

USE_COLOR = True  # toggled by --no-color


def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if USE_COLOR else text


# ──────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────
@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW
    secret: str
    context: str
    entropy: float = 0.0


# ──────────────────────────────────────────────
# Rule definitions
# Each entry: (rule_name, severity, compiled_pattern)
# ──────────────────────────────────────────────
@dataclass
class Rule:
    name: str
    severity: str
    pattern: re.Pattern[str]


RULES: list[Rule] = [
    # ── Cloud / AWS ──────────────────────────
    Rule("aws_access_key_id",
         "CRITICAL",
         re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b")),
    Rule("aws_secret_access_key",
         "CRITICAL",
         re.compile(r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[:=]\s*['\"]?([A-Za-z0-9+/]{40})['\"]?")),

    # ── GCP ──────────────────────────────────
    Rule("google_api_key",
         "HIGH",
         re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    Rule("gcp_service_account",
         "CRITICAL",
         re.compile(r'"type"\s*:\s*"service_account"')),
    Rule("firebase_url",
         "HIGH",
         re.compile(r"https://[a-zA-Z0-9\-]+\.firebaseio\.com")),

    # ── Azure ─────────────────────────────────
    Rule("azure_storage_key",
         "CRITICAL",
         re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+")),
    Rule("azure_sas_token",
         "HIGH",
         re.compile(r"(?i)sig=[A-Za-z0-9%+/=]{20,}")),
    Rule("azure_client_secret",
         "CRITICAL",
         re.compile(r"(?i)client[_\-]?secret\s*[:=]\s*['\"]?[A-Za-z0-9~._\-]{34,}['\"]?")),

    # ── GitHub ────────────────────────────────
    Rule("github_pat",
         "CRITICAL",
         re.compile(r"\bghp_[A-Za-z0-9_]{36}\b")),
    Rule("github_oauth",
         "CRITICAL",
         re.compile(r"\bgho_[A-Za-z0-9_]{36}\b")),
    Rule("github_app_token",
         "CRITICAL",
         re.compile(r"\bghu_[A-Za-z0-9_]{36}\b")),
    Rule("github_refresh_token",
         "HIGH",
         re.compile(r"\bghr_[A-Za-z0-9_]{36}\b")),
    Rule("github_server_token",
         "CRITICAL",
         re.compile(r"\bghs_[A-Za-z0-9_]{36}\b")),

    # ── GitLab ───────────────────────────────
    Rule("gitlab_pat",
         "CRITICAL",
         re.compile(r"\bglpat-[A-Za-z0-9\-_]{20}\b")),
    Rule("gitlab_pipeline_trigger",
         "HIGH",
         re.compile(r"\bglptt-[A-Za-z0-9\-_]{20}\b")),

    # ── Slack ─────────────────────────────────
    Rule("slack_token",
         "HIGH",
         re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    Rule("slack_webhook",
         "HIGH",
         re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+")),

    # ── Stripe ───────────────────────────────
    Rule("stripe_secret_key",
         "CRITICAL",
         re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    Rule("stripe_publishable_key",
         "MEDIUM",
         re.compile(r"\bpk_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    Rule("stripe_restricted_key",
         "HIGH",
         re.compile(r"\brk_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    Rule("stripe_webhook_secret",
         "HIGH",
         re.compile(r"\bwhsec_[A-Za-z0-9]{32,}\b")),

    # ── Twilio ───────────────────────────────
    Rule("twilio_account_sid",
         "HIGH",
         re.compile(r"\bAC[a-z0-9]{32}\b")),
    Rule("twilio_auth_token",
         "CRITICAL",
         re.compile(r"(?i)twilio[_\-]?auth[_\-]?token\s*[:=]\s*['\"]?[a-z0-9]{32}['\"]?")),

    # ── SendGrid / Mailgun ────────────────────
    Rule("sendgrid_api_key",
         "HIGH",
         re.compile(r"\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}\b")),
    Rule("mailgun_api_key",
         "HIGH",
         re.compile(r"\bkey-[a-f0-9]{32}\b")),

    # ── NPM ──────────────────────────────────
    Rule("npm_token",
         "HIGH",
         re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),

    # ── Telegram ─────────────────────────────
    Rule("telegram_bot_token",
         "HIGH",
         re.compile(r"\b\d{8,10}:AA[A-Za-z0-9\-_]{33}\b")),

    # ── Discord ──────────────────────────────
    Rule("discord_bot_token",
         "HIGH",
         re.compile(r"\b[MN][A-Za-z0-9\-_]{23}\.[\w\-]{6}\.[\w\-]{27}\b")),
    Rule("discord_webhook",
         "MEDIUM",
         re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+")),

    # ── Heroku ───────────────────────────────
    Rule("heroku_api_key",
         "CRITICAL",
         re.compile(r"(?i)heroku[_\-]?api[_\-]?key\s*[:=]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?")),

    # ── Shopify ──────────────────────────────
    Rule("shopify_private_app_token",
         "CRITICAL",
         re.compile(r"\bshppa_[A-Za-z0-9]{32}\b")),
    Rule("shopify_shared_secret",
         "HIGH",
         re.compile(r"\bshpss_[A-Za-z0-9]{32}\b")),
    Rule("shopify_access_token",
         "CRITICAL",
         re.compile(r"\bshpat_[A-Za-z0-9]{32}\b")),

    # ── JWT ──────────────────────────────────
    Rule("jwt_token",
         "MEDIUM",
         re.compile(r"\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]*")),

    # ── Private Keys ─────────────────────────
    Rule("rsa_private_key",
         "CRITICAL",
         re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")),
    Rule("dsa_private_key",
         "CRITICAL",
         re.compile(r"-----BEGIN DSA PRIVATE KEY-----")),
    Rule("ec_private_key",
         "CRITICAL",
         re.compile(r"-----BEGIN EC PRIVATE KEY-----")),
    Rule("openssh_private_key",
         "CRITICAL",
         re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    Rule("pgp_private_key",
         "CRITICAL",
         re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")),
    Rule("certificate",
         "LOW",
         re.compile(r"-----BEGIN CERTIFICATE-----")),

    # ── Database connection strings ───────────
    Rule("postgres_uri",
         "CRITICAL",
         re.compile(r"postgres(?:ql)?://[^:]+:[^@]+@[^\s\"'`]+")),
    Rule("mysql_uri",
         "CRITICAL",
         re.compile(r"mysql://[^:]+:[^@]+@[^\s\"'`]+")),
    Rule("mongodb_uri",
         "CRITICAL",
         re.compile(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s\"'`]+")),
    Rule("redis_uri",
         "HIGH",
         re.compile(r"redis://(?:[^:]+:[^@]+@)[^\s\"'`]+")),

    # ── Generic patterns ─────────────────────
    Rule("bearer_token",
         "HIGH",
         re.compile(r"(?i)Authorization\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9\-_=.]+['\"]?")),
    Rule("basic_auth_header",
         "HIGH",
         re.compile(r"(?i)Authorization\s*[:=]\s*['\"]?Basic\s+[A-Za-z0-9+/=]{20,}['\"]?")),
    Rule("generic_secret",
         "MEDIUM",
         re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|auth[_\-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{20,}['\"]?")),
    Rule("dotenv_secret",
         "MEDIUM",
         re.compile(r"^(?!#)[A-Z_]+(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|AUTH)\s*=\s*.{8,}", re.MULTILINE)),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     YELLOW + BOLD,
    "MEDIUM":   CYAN,
    "LOW":      GREY,
}

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".mypy_cache", ".pytest_cache",
    "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".eggs", "target", "vendor",
}

TEXT_EXTENSIONS = {
    ".cfg", ".conf", ".config", ".env", ".envrc",
    ".ini", ".properties", ".toml",
    ".json", ".json5", ".yaml", ".yml",
    ".xml", ".html", ".htm",
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rb", ".java", ".kt", ".swift",
    ".php", ".cs", ".rs", ".cpp", ".c", ".h",
    ".sh", ".bash", ".zsh", ".fish", ".ps1",
    ".tf", ".tfvars", ".hcl",
    ".md", ".txt", ".log",
    ".pem", ".key", ".crt", ".pub",
    ".gradle", ".mvn",
    ".npmrc", ".yarnrc", ".dockerignore",
    "Dockerfile", ".dockerfile",
}


# ──────────────────────────────────────────────
# Entropy helpers
# ──────────────────────────────────────────────

def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    ent = 0.0
    length = len(value)
    for count in counts.values():
        p = count / length
        ent -= p * math.log2(p)
    return round(ent, 3)


def likely_secret(value: str, min_len: int = 20, min_entropy: float = 3.5) -> bool:
    candidate = value.strip().strip("'\"`)")
    if len(candidate) < min_len:
        return False
    if candidate.isdigit():
        return False
    char_classes = sum([
        any(ch.islower() for ch in candidate),
        any(ch.isupper() for ch in candidate),
        any(ch.isdigit() for ch in candidate),
        any(ch in "+/=_-@$!%^&*()" for ch in candidate),
    ])
    if char_classes < 3:
        return False
    return shannon_entropy(candidate) >= min_entropy


# ──────────────────────────────────────────────
# File helpers
# ──────────────────────────────────────────────

def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS or path.name in TEXT_EXTENSIONS:
        return True
    try:
        with path.open("rb") as fh:
            chunk = fh.read(8192)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    try:
        chunk.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass
    try:
        chunk.decode("latin-1")
        return True
    except UnicodeDecodeError:
        return False


def iter_files(root: Path, follow_symlinks: bool = False,
               exclude_patterns: list[re.Pattern[str]] | None = None) -> Iterable[Path]:
    for cur_root, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
        ]
        for filename in filenames:
            candidate = Path(cur_root) / filename
            if candidate.is_symlink() and not follow_symlinks:
                continue
            if exclude_patterns:
                rel = str(candidate)
                if any(pat.search(rel) for pat in exclude_patterns):
                    continue
            yield candidate


# ──────────────────────────────────────────────
# Core scanner
# ──────────────────────────────────────────────

def scan_file(path: Path, min_severity: str = "LOW",
              high_entropy_scan: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    seen: set[tuple[int, str, str]] = set()

    def add(finding: Finding) -> None:
        key = (finding.line, finding.rule, finding.secret[:30])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for rule in RULES:
            if SEVERITY_ORDER[rule.severity] > SEVERITY_ORDER[min_severity]:
                continue
            for match in rule.pattern.finditer(line):
                raw = match.group(0)
                # extra check for generic_secret / dotenv_secret
                if rule.name in ("generic_secret", "dotenv_secret", "basic_auth_header"):
                    candidate = raw.split("=", 1)[-1].split(":", 1)[-1].strip().strip("'\"")
                    if not likely_secret(candidate, min_len=12, min_entropy=3.2):
                        continue
                ent = shannon_entropy(raw)
                add(Finding(
                    file=str(path),
                    line=lineno,
                    rule=rule.name,
                    severity=rule.severity,
                    secret=raw,
                    context=line.strip()[:200],
                    entropy=ent,
                ))

        # High-entropy token sweep (catches undocumented tokens)
        if high_entropy_scan:
            for token in re.findall(r"[A-Za-z0-9+/=_\-]{32,}", line):
                if likely_secret(token, min_len=32, min_entropy=4.0):
                    add(Finding(
                        file=str(path),
                        line=lineno,
                        rule="high_entropy_token",
                        severity="MEDIUM",
                        secret=token,
                        context=line.strip()[:200],
                        entropy=shannon_entropy(token),
                    ))

    return findings


def scan_paths(
    targets: list[Path],
    skip_binary: bool = True,
    follow_symlinks: bool = False,
    min_severity: str = "LOW",
    high_entropy_scan: bool = True,
    exclude_patterns: list[re.Pattern[str]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for target in targets:
        if target.is_file():
            if skip_binary and not is_text_file(target):
                continue
            findings.extend(scan_file(target, min_severity, high_entropy_scan))
        elif target.is_dir():
            for path in iter_files(target, follow_symlinks, exclude_patterns):
                if skip_binary and not is_text_file(path):
                    continue
                findings.extend(scan_file(path, min_severity, high_entropy_scan))
        else:
            print(color(f"[WARN] skipping unknown path: {target}", YELLOW), file=sys.stderr)

    # Sort: severity first, then file path, then line number
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line))
    return findings


# ──────────────────────────────────────────────
# Output helpers
# ──────────────────────────────────────────────

def redact(secret: str) -> str:
    """Show first 4 and last 4 chars, mask the rest."""
    if len(secret) <= 12:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def print_findings(findings: list[Finding], show_secrets: bool = False) -> None:
    current_file = None
    for f in findings:
        if f.file != current_file:
            current_file = f.file
            print(f"\n{color(f.file, BOLD + MAGENTA)}")

        sev_col = SEVERITY_COLOR.get(f.severity, "")
        sev_tag = color(f"[{f.severity}]", sev_col)
        rule_tag = color(f"[{f.rule}]", CYAN)
        secret_display = f.secret if show_secrets else redact(f.secret)

        print(f"  {color(str(f.line), GREY)}  {sev_tag} {rule_tag}  "
              f"entropy={color(str(f.entropy), GREY)}")
        print(f"       secret : {color(secret_display, YELLOW)}")
        print(f"       context: {color(f.context, GREY)}")


def print_summary(findings: list[Finding]) -> None:
    if not findings:
        print(color("\n✔  No secrets found.", GREEN))
        return

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    files_hit = len({f.file for f in findings})
    total = len(findings)

    print(color(f"\n── Summary ──────────────────────────────", BOLD))
    print(f"  Files with findings : {color(str(files_hit), YELLOW)}")
    print(f"  Total findings      : {color(str(total), RED if total else GREEN)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = counts.get(sev, 0)
        if n:
            print(f"    {color(sev, SEVERITY_COLOR[sev]):<20}  {n}")
    print()


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secretsyoucantkeep",
        description="Scan files/folders for exposed secrets (bug bounty edition).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s .                          # scan current folder
  %(prog)s /path/to/repo              # scan a repo
  %(prog)s file.env secrets.yaml      # scan specific files
  %(prog)s . --severity HIGH          # only HIGH and CRITICAL
  %(prog)s . --json -o findings.json  # dump JSON
  %(prog)s . --show-secrets           # print full secret values
  %(prog)s . --exclude "test|mock"    # skip paths matching regex
        """,
    )
    p.add_argument("paths", nargs="*", default=["."],
                   help="Files or directories to scan (default: current directory)")
    p.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   default="LOW", help="Minimum severity to report (default: LOW)")
    p.add_argument("--json", action="store_true",
                   help="Output results as JSON")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write output to FILE instead of stdout")
    p.add_argument("--show-secrets", action="store_true",
                   help="Print full secret values (default: redacted)")
    p.add_argument("--no-entropy", action="store_true",
                   help="Disable high-entropy token sweep")
    p.add_argument("--follow-symlinks", action="store_true",
                   help="Follow symlinks")
    p.add_argument("--no-skip-binary", action="store_true",
                   help="Attempt to scan binary files")
    p.add_argument("--exclude", metavar="REGEX", action="append", default=[],
                   help="Exclude paths matching this regex (repeatable)")
    p.add_argument("--no-color", action="store_true",
                   help="Disable colored output")
    p.add_argument("--list-rules", action="store_true",
                   help="Print all built-in rules and exit")
    return p


def main(argv: list[str]) -> int:
    global USE_COLOR

    args = build_parser().parse_args(argv)

    if args.no_color:
        USE_COLOR = False

    if args.list_rules:
        print(f"{'Rule':<35} {'Severity':<10} Pattern")
        print("-" * 90)
        for rule in RULES:
            print(f"{rule.name:<35} {rule.severity:<10} {rule.pattern.pattern[:45]}")
        return 0

    targets = [Path(p).resolve() for p in args.paths]
    missing = [t for t in targets if not t.exists()]
    if missing:
        for m in missing:
            print(color(f"error: path does not exist: {m}", RED), file=sys.stderr)
        return 2

    exclude_patterns = [re.compile(pat) for pat in args.exclude] if args.exclude else None

    findings = scan_paths(
        targets=targets,
        skip_binary=not args.no_skip_binary,
        follow_symlinks=args.follow_symlinks,
        min_severity=args.severity,
        high_entropy_scan=not args.no_entropy,
        exclude_patterns=exclude_patterns,
    )

    # Produce output
    if args.json:
        output_text = json.dumps([asdict(f) for f in findings], indent=2)
    else:
        # Capture colored output for stdout or redirect to file
        import io
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        print_findings(findings, show_secrets=args.show_secrets)
        print_summary(findings)
        sys.stdout = old_stdout
        output_text = buf.getvalue()

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(output_text, encoding="utf-8")
        print(color(f"Results written to {out_path}", GREEN))
    else:
        print(output_text, end="")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
