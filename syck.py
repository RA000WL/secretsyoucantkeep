#!/usr/bin/env python3
"""
syck.py — local secrets scanner for bug bounty hunters.
Scans files and folders for exposed credentials, tokens, and keys.

By default secrets are printed IN FULL so you can paste them straight into
a bug bounty report. Use --redact to mask them in the output.
"""
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import math
import os
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html import escape as html_escape
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

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
# Each entry: Rule(name, severity, compiled_pattern)
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
    Rule("aws_session_token",
         "CRITICAL",
         re.compile(r"(?i)aws[_\-\.]?session[_\-\.]?token\s*[:=]\s*['\"]?[A-Za-z0-9+/=]{16,}['\"]?")),

    # ── GCP ──────────────────────────────────
    Rule("google_api_key",
         "HIGH",
         re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    Rule("google_oauth_token",
         "HIGH",
         re.compile(r"\bya29\.[A-Za-z0-9\-_]{20,}\b")),
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
         re.compile(r"(?i)(?:&|\?|^)sig=[A-Za-z0-9%+/=]{20,}")),
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
    Rule("github_fine_grained_pat",
         "CRITICAL",
         re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}\b")),

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
    Rule("twilio_api_key_sid",
         "CRITICAL",
         re.compile(r"\bSK[a-f0-9]{32}\b")),
    Rule("twilio_auth_token",
         "CRITICAL",
         re.compile(r"(?i)twilio[_\-]?auth[_\-]?token\s*[:=]\s*['\"]?[a-z0-9]{32}['\"]?")),

    # ── SendGrid / Mailgun / Mailchimp / Brevo ─
    Rule("sendgrid_api_key",
         "HIGH",
         re.compile(r"\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}\b")),
    Rule("mailgun_api_key",
         "HIGH",
         re.compile(r"\bkey-[a-f0-9]{32}\b")),
    Rule("mailchimp_api_key",
         "HIGH",
         re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b")),
    Rule("brevo_sendinblue_key",
         "HIGH",
         re.compile(r"\bxkeysib-[A-Za-z0-9]{64}-[A-Za-z0-9]{32}\b")),

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

    # ── AI Providers ──────────────────────────
    Rule("openai_api_key",
         "CRITICAL",
         re.compile(r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b")),
    Rule("openai_project_key",
         "CRITICAL",
         re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{40,}\b")),
    Rule("openai_service_account_key",
         "CRITICAL",
         re.compile(r"\bsk-svcacct-[A-Za-z0-9_\-]{40,}\b")),
    Rule("anthropic_api_key",
         "CRITICAL",
         re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{32,}\b")),
    Rule("anthropic_admin_key",
         "CRITICAL",
         re.compile(r"\bsk-ant-admin-[A-Za-z0-9\-_]{32,}\b")),
    Rule("huggingface_token",
         "HIGH",
         re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    Rule("replicate_api_token",
         "HIGH",
         re.compile(r"\br8_[A-Za-z0-9]{30,}\b")),
    Rule("cohere_api_key",
         "HIGH",
         re.compile(r"\bco-[A-Za-z0-9]{30,}\b")),
    Rule("groq_api_key",
         "HIGH",
         re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b")),
    Rule("perplexity_api_key",
         "HIGH",
         re.compile(r"\bpplx-[A-Za-z0-9]{40,}\b")),

    # ── Modern SaaS ───────────────────────────
    Rule("supabase_url",
         "LOW",
         re.compile(r"https://[a-z0-9]{20,}\.supabase\.co")),
    Rule("planetscale_password",
         "CRITICAL",
         re.compile(r"\bpscale_pw_[A-Za-z0-9_\-]{40,}\b")),
    Rule("planetscale_token",
         "CRITICAL",
         re.compile(r"\bpscale_tkn_[A-Za-z0-9_\-]{40,}\b")),
    Rule("digitalocean_pat",
         "CRITICAL",
         re.compile(r"\bdop_v1_[a-f0-9]{64}\b")),
    Rule("cloudflare_api_key",
         "HIGH",
         re.compile(r"(?i)cloudflare[_\-]?api[_\-]?key\s*[:=]\s*['\"]?[0-9a-f]{32,}['\"]?")),
    Rule("cloudflare_api_token",
         "CRITICAL",
         re.compile(r"(?i)CF_API_TOKEN\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{40}['\"]?")),
    Rule("vercel_token",
         "CRITICAL",
         re.compile(r"\bvercel_[A-Za-z0-9]{24,}\b")),
    Rule("linear_api_key",
         "HIGH",
         re.compile(r"\blin_api_[A-Za-z0-9]{40,}\b")),
    Rule("ngrok_authtoken",
         "HIGH",
         re.compile(r"(?i)ngrok[_\-]?auth[_\-]?token\s*[:=]\s*['\"]?[0-9a-zA-Z_]{40,}['\"]?")),

    # ── Observability / DevOps ────────────────
    Rule("new_relic_key",
         "HIGH",
         re.compile(r"\bNRAK-[A-Z0-9]{27}\b")),
    Rule("new_relic_api_key",
         "HIGH",
         re.compile(r"(?i)new[_\-]?relic[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['\"]?[A-Za-z0-9\-]{20,}['\"]?")),
    Rule("datadog_api_key",
         "HIGH",
         re.compile(r"(?i)datadog[_\-]?api[_\-]?key\s*[:=]\s*['\"]?[A-Za-z0-9]{32,}['\"]?")),
    Rule("sentry_dsn",
         "MEDIUM",
         re.compile(r"https://[a-f0-9]{32}@[a-z0-9.]+\.sentry\.io/\d+")),
    Rule("pulumi_token",
         "CRITICAL",
         re.compile(r"\bpul-[A-Za-z0-9]{40,}\b")),

    # ── HashiCorp Vault / Infra ───────────────
    Rule("vault_service_token",
         "CRITICAL",
         re.compile(r"\bhvs\.[A-Za-z0-9_\-]{24,}\b")),
    Rule("vault_batch_token",
         "HIGH",
         re.compile(r"\bhvb\.[A-Za-z0-9_\-]{24,}\b")),
    Rule("vault_recovery_token",
         "CRITICAL",
         re.compile(r"\bhvr\.[A-Za-z0-9_\-]{24,}\b")),
    Rule("docker_hub_pat",
         "CRITICAL",
         re.compile(r"\bdckr_pat_[A-Za-z0-9_\-]{20,}\b")),
    Rule("pypi_token",
         "CRITICAL",
         re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b")),
    Rule("rubygems_api_key",
         "CRITICAL",
         re.compile(r"\brubygems_[a-f0-9]{48}\b")),
    Rule("terraform_cloud_token",
         "CRITICAL",
         re.compile(r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67,}\b")),

    # ── Payment / Commerce ────────────────────
    Rule("square_access_token",
         "CRITICAL",
         re.compile(r"\bsq0atp-[A-Za-z0-9_\-]{22}\b")),
    Rule("square_oauth_secret",
         "CRITICAL",
         re.compile(r"\bsq0csp-[A-Za-z0-9_\-]{32}\b")),
    Rule("paypal_client_secret",
         "CRITICAL",
         re.compile(r"(?i)paypal[_\-]?client[_\-]?secret\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?")),

    # ── Maps / Geo ────────────────────────────
    Rule("mapbox_secret_token",
         "HIGH",
         re.compile(r"\bsk\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+")),
    Rule("mapbox_public_token",
         "LOW",
         re.compile(r"\bpk\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+")),

    # ── Monitoring ────────────────────────────
    Rule("dynatrace_api_token",
         "CRITICAL",
         re.compile(r"\bdt0[a-zA-Z][0-9]{2}\.[A-Za-z0-9]{20,}\.[A-Za-z0-9]{20,}\b")),

    # ── Identity ──────────────────────────────
    Rule("okta_api_token",
         "CRITICAL",
         re.compile(r"\b00[A-Za-z0-9_\-]{40}\b")),

    # ── Misc SaaS ─────────────────────────────
    Rule("dropbox_token",
         "HIGH",
         re.compile(r"\bsl\.[A-Za-z0-9_\-]{20,}\b")),
    Rule("asana_pat",
         "HIGH",
         re.compile(r"\b[0-9]/[0-9]{16,}:[A-F0-9]{32}\b")),

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
         re.compile(r"postgres(?:ql)?://[^:\s\"'`]+:[^@\s\"'`]+@[^\s\"'`]+")),
    Rule("mysql_uri",
         "CRITICAL",
         re.compile(r"mysql://[^:\s\"'`]+:[^@\s\"'`]+@[^\s\"'`]+")),
    Rule("mongodb_uri",
         "CRITICAL",
         re.compile(r"mongodb(?:\+srv)?://[^:\s\"'`]+:[^@\s\"'`]+@[^\s\"'`]+")),
    Rule("redis_uri",
         "HIGH",
         re.compile(r"redis://(?:[^:\s\"'`]+:[^@\s\"'`]+@)[^\s\"'`]+")),

    # ── Infrastructure ───────────────────────
    Rule("docker_auth_config",
         "HIGH",
         re.compile(r'"auths"\s*:\s*\{')),
    Rule("kubernetes_secret",
         "CRITICAL",
         re.compile(r"(?ms)apiVersion:\s*v1\s*\nkind:\s*Secret\b")),
    Rule("ssh_password",
         "HIGH",
         re.compile(r"(?i)\bssh[_\-]?password\s*[:=]\s*['\"]?[^\s'\",]{8,}['\"]?")),
    Rule("smtp_password",
         "HIGH",
         re.compile(r"(?i)\bsmtp[_\-]?password\s*[:=]\s*['\"]?[^\s'\",]{6,}['\"]?")),
    Rule("ftp_password",
         "HIGH",
         re.compile(r"(?i)\bftp[_\-]?(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\",]{6,}['\"]?")),

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
SEVERITY_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
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

DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024   # 10 MB
DEFAULT_WORKERS = 4


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


def parse_size(value: str | int) -> int:
    """Accepts '4096', '512K', '10M', '2G' (case-insensitive)."""
    if isinstance(value, int):
        return value
    s = str(value).strip().upper().replace("IB", "")
    multipliers = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    for suffix, mul in multipliers.items():
        if s.endswith(suffix):
            try:
                return int(float(s.removesuffix(suffix)) * mul)
            except ValueError:
                pass
    raise argparse.ArgumentTypeError(f"invalid size value: {value!r}")


def iter_files(root: Path, follow_symlinks: bool = False,
               exclude_patterns: list[re.Pattern[str]] | None = None,
               max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> Iterable[Path]:
    for cur_root, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
        ]
        for filename in filenames:
            candidate = Path(cur_root) / filename
            if candidate.is_symlink() and not follow_symlinks:
                continue
            if max_file_size:
                try:
                    if candidate.stat().st_size > max_file_size:
                        continue
                except OSError:
                    continue
            if exclude_patterns:
                rel = str(candidate)
                if any(pat.search(rel) for pat in exclude_patterns):
                    continue
            yield candidate


# ──────────────────────────────────────────────
# Core scanner
# ──────────────────────────────────────────────

# Pre-compute severity ranks so we can skip rules cheaply
_RULE_RANK: dict[str, int] = {r.name: SEVERITY_ORDER[r.severity] for r in RULES}
_MIN_RANK: int = SEVERITY_ORDER["LOW"]


def load_custom_rules(path: str) -> list[Rule]:
    """Load additional rules from a JSON file.

    Expected format:

        [
          {
            "name": "my_rule",
            "severity": "HIGH",
            "pattern": "regex-pattern-here"
          },
          ...
        ]
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(color(f"[!] failed to load custom rules: {e}", RED), file=sys.stderr)
        sys.exit(2)
    if not isinstance(data, list):
        print(color("[!] custom rules file must contain a JSON array", RED), file=sys.stderr)
        sys.exit(2)
    rules: list[Rule] = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            print(color(f"[!] rule at index {i} must be a JSON object", RED), file=sys.stderr)
            sys.exit(2)
        name = entry.get("name", f"custom_{i}")
        severity = entry.get("severity", "MEDIUM").upper()
        pattern_str = entry.get("pattern")
        if not pattern_str:
            print(color(f"[!] rule '{name}' is missing 'pattern' field", RED), file=sys.stderr)
            sys.exit(2)
        if severity not in SEVERITY_ORDER:
            print(color(f"[!] rule '{name}' has invalid severity '{severity}'", RED), file=sys.stderr)
            sys.exit(2)
        try:
            pattern = re.compile(pattern_str)
        except re.error as e:
            print(color(f"[!] rule '{name}' has invalid regex: {e}", RED), file=sys.stderr)
            sys.exit(2)
        rules.append(Rule(name, severity, pattern))
    return rules


# Pre-compiled regexes used by the high-entropy sweep.  Compiled once
# at module load instead of on every line of every file.
_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")
# Only run the entropy sweep on lines that look like they could carry
# a secret.  Without this filter minified JS, source maps and JSON
# configs full of base64 blobs produce huge numbers of false-positive
# "high entropy" findings.  Keywords are case-insensitive.
_SECRET_CONTEXT_RE = re.compile(
    r"(?i)\b(?:"
    r"api[_-]?key|apikey|"
    r"secret|secret[_-]?key|"
    r"password|passwd|pwd|"
    r"token|bearer|"
    r"auth(?:orization)?|credential|"
    r"private[_-]?key|access[_-]?key|"
    r"client[_-]?(?:id|secret)|"
    r"aws|gcp|azure|s3|"
    r"encryption[_-]?key|signing[_-]?key|"
    r"jwt|oauth|"
    r"ssh[_-]?key"
    r")\b"
)


def _is_minified_js(path: Path, content: str) -> bool:
    """Heuristics for minified/bundled JS.  These files contain thousands
    of long alphanumeric tokens (variable names, base64 data URIs, hash
    constants) that all look high-entropy — running the entropy sweep
    on them produces pure noise."""
    name = path.name.lower()
    if name.endswith((".min.js", ".bundle.js", ".min.mjs")):
        return True
    if not (name.endswith(".js") or name.endswith(".mjs")):
        return False
    if len(content) < 5000:
        return False
    nlines = content.count("\n")
    if nlines == 0:
        return True
    avg = len(content) / nlines
    # Minified JS is typically 1-3 huge lines, or has a very high
    # average line length.
    return nlines <= 3 or avg > 2000


# ──────────────────────────────────────────────
# Base64-decoding pipeline
# ──────────────────────────────────────────────

_BASE64_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}(?!\w)")
_BASE64_MIN_LEN = 32


def _decode_and_rescan(line: str, path: Path, lineno: int,
                       rules: list[Rule], min_rank: int,
                       add_fn) -> None:
    """Find base64 strings in *line*, decode them, and re-run rules on the
    decoded plaintext.  Findings are tagged ``base64_<rulename>``."""
    for match in _BASE64_CANDIDATE_RE.finditer(line):
        raw = match.group(0)
        # Quick sanity: base64 length must be valid
        if len(raw) < _BASE64_MIN_LEN:
            continue
        try:
            decoded_bytes = base64.b64decode(raw)
        except Exception:
            continue
        try:
            decoded_text = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # Skip if the decoded output is binary or entirely non-printable
        printable = sum(1 for ch in decoded_text if ch.isprintable() or ch in "\n\r\t")
        if printable < len(decoded_text) // 2:
            continue

        for rule in rules:
            if _RULE_RANK.get(rule.name, 99) > min_rank:
                continue
            for m in rule.pattern.finditer(decoded_text):
                secret = m.group(0)
                add_fn(Finding(
                    file=str(path),
                    line=lineno,
                    rule=f"base64_{rule.name}",
                    severity=rule.severity,
                    secret=secret,
                    context=f"base64 decoded: {decoded_text[:200]}",
                    entropy=shannon_entropy(secret),
                ))


# ──────────────────────────────────────────────
# JSON-aware scanning
# ──────────────────────────────────────────────

# Keys whose string values should always be treated as potential secrets
_JSON_SECRET_KEYS = re.compile(
    r"(?i)^(?:"
    r"password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|access[_-]?token|auth[_-]?token|auth[_-]?key|"
    r"client[_-]?secret|client[_-]?id|"
    r"private[_-]?key|ssh[_-]?key|"
    r"encryption[_-]?key|signing[_-]?key|"
    r"bearer|credential|refresh[_-]?token|"
    r"session[_-]?key|secret[_-]?key|master[_-]?key"
    r")$"
)

_JSON_MAX_SCAN_SIZE = 10 * 1024 * 1024  # skip files larger than 10 MB


def _scan_json_value(value: object, key_path: str, path: Path,
                     rules: list[Rule], min_rank: int, add_fn) -> None:
    """Recursively walk a parsed JSON tree and flag secret-like values."""
    if isinstance(value, dict):
        for k, v in value.items():
            kp = f"{key_path}.{k}" if key_path else k
            _scan_json_value(v, kp, path, rules, min_rank, add_fn)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _scan_json_value(v, f"{key_path}[{i}]", path, rules, min_rank, add_fn)
    elif isinstance(value, str):
        if not value:
            return
        key_name = key_path.rsplit(".", 1)[-1] if "." in key_path else key_path
        # If the key itself looks secret-worthy, flag the value (entropy gate)
        if _JSON_SECRET_KEYS.match(key_name):
            ent = shannon_entropy(value)
            if len(value) >= 8 and not value.isdigit() and ent >= 3.0:
                add_fn(Finding(
                    file=str(path),
                    line=0,
                    rule=f"json_{key_name}",
                    severity="MEDIUM",
                    secret=value[:500],
                    context=f"json key: {key_path}",
                    entropy=ent,
                ))
        # Also run all rule patterns against the value
        for rule in rules:
            if _RULE_RANK.get(rule.name, 99) > min_rank:
                continue
            for m in rule.pattern.finditer(value):
                secret = m.group(0)
                add_fn(Finding(
                    file=str(path),
                    line=0,
                    rule=f"json_{rule.name}",
                    severity=rule.severity,
                    secret=secret,
                    context=f"json key: {key_path}",
                    entropy=shannon_entropy(secret),
                ))


def _scan_json_file(path: Path, content: str, rules: list[Rule],
                    min_rank: int, add_fn) -> None:
    """Parse *content* as JSON and run structure-aware secret scanning."""
    if not path.suffix.lower() == ".json":
        return
    if len(content) > _JSON_MAX_SCAN_SIZE:
        return
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return
    _scan_json_value(data, "", path, rules, min_rank, add_fn)


def scan_file(path: Path, min_severity: str = "LOW",
              high_entropy_scan: bool = True,
              decode_base64: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    # Skip the high-entropy sweep on minified/bundled JS — these files
    # have thousands of long tokens (variable names, base64 data URIs,
    # hash constants) that all look high-entropy.  The pattern-based
    # rules above still run, so real keys won't be missed.
    entropy_eligible = high_entropy_scan and not _is_minified_js(path, content)

    seen: set[tuple[int, str, str]] = set()
    min_rank = SEVERITY_ORDER[min_severity]

    def add(finding: Finding) -> None:
        key = (finding.line, finding.rule, finding.secret[:30])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for rule in RULES:
            if _RULE_RANK[rule.name] > min_rank:
                continue
            for match in rule.pattern.finditer(line):
                raw = match.group(0)
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

        if entropy_eligible and _SECRET_CONTEXT_RE.search(line):
            # Only run the entropy sweep on lines that look like they
            # could carry a secret.  This is the main fix for the
            # "the whole minified JS file is reported as high entropy"
            # false positive.
            for token in _ENTROPY_TOKEN_RE.findall(line):
                if likely_secret(token, min_len=32, min_entropy=4.5):
                    add(Finding(
                        file=str(path),
                        line=lineno,
                        rule="high_entropy_token",
                        severity="MEDIUM",
                        secret=token,
                        context=line.strip()[:200],
                        entropy=shannon_entropy(token),
                    ))

        # Base64 decode + re-scan (opt-in)
        if decode_base64:
            _decode_and_rescan(line, path, lineno, RULES, min_rank, add)

    # JSON-aware scanning (automatic for .json files)
    _scan_json_file(path, content, RULES, min_rank, add)

    return findings


def _collect_files(targets: list[Path], skip_binary: bool,
                   follow_symlinks: bool,
                   exclude_patterns: list[re.Pattern[str]] | None,
                   max_file_size: int) -> list[Path]:
    files: list[Path] = []
    for target in targets:
        if target.is_file():
            if _should_skip_file(target):
                continue
            if skip_binary and not is_text_file(target):
                continue
            if max_file_size:
                try:
                    if target.stat().st_size > max_file_size:
                        continue
                except OSError:
                    continue
            files.append(target)
        elif target.is_dir():
            for path in iter_files(target, follow_symlinks, exclude_patterns, max_file_size):
                if _should_skip_file(path):
                    continue
                if skip_binary and not is_text_file(path):
                    continue
                files.append(path)
        else:
            print(color(f"[WARN] skipping unknown path: {target}", YELLOW), file=sys.stderr)
    return files


_SKIP_SUFFIXES = (".map",)  # source maps, full of base64 noise


def _should_skip_file(path: Path) -> bool:
    return path.suffix.lower() in _SKIP_SUFFIXES


def _safe_name_from_url(url: str) -> str:
    """Pick a filesystem-safe filename based on the URL's last segment."""
    last = url.split("?", 1)[0].rsplit("/", 1)[-1] or "index.html"
    name = "".join(c for c in last if c.isalnum() or c in "._-")
    if not name:
        name = "index.html"
    return name[:80]


def _fetch_url(url: str, dest_dir: Path, timeout: int = 20) -> Path | None:
    """Download a single URL into dest_dir.  Returns the local path on
    success, None on any error.  Network errors are non-fatal — the
    caller just skips the URL."""
    name = _safe_name_from_url(url)
    dest = dest_dir / name
    i = 1
    while dest.exists():
        stem, suf = dest.stem, dest.suffix
        dest = dest_dir / f"{stem}_{i}{suf}"
        i += 1
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "syck/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(color(f"[!] failed to fetch {url}: {exc}", YELLOW),
              file=sys.stderr)
        return None
    if not data:
        return None
    try:
        dest.write_bytes(data)
    except OSError as exc:
        print(color(f"[!] failed to write {dest}: {exc}", YELLOW),
              file=sys.stderr)
        return None
    print(color(f"[+] fetched {url} → {dest.name} ({len(data):,} bytes)",
                GREY), file=sys.stderr)
    return dest


def scan_paths(
    targets: list[Path],
    skip_binary: bool = True,
    follow_symlinks: bool = False,
    min_severity: str = "LOW",
    high_entropy_scan: bool = True,
    decode_base64: bool = False,
    exclude_patterns: list[re.Pattern[str]] | None = None,
    workers: int = DEFAULT_WORKERS,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    progress: bool = False,
) -> list[Finding]:
    files = _collect_files(targets, skip_binary, follow_symlinks,
                           exclude_patterns, max_file_size)

    # Auto-enable progress for larger scans
    show_progress = progress or len(files) > 20

    if show_progress:
        print(color(f"[*] Scanning {len(files)} file(s) with {workers} worker(s)…", GREY),
              file=sys.stderr)

    findings: list[Finding] = []
    total = len(files)
    done = 0

    if total == 0:
        return findings

    if workers <= 1 or total <= 1:
        for f in files:
            findings.extend(scan_file(f, min_severity, high_entropy_scan, decode_base64))
            done += 1
            if show_progress and done % max(1, total // 20) == 0:
                print(color(f"\r  [{done}/{total}] files scanned…", GREY),
                      end="", file=sys.stderr)
        if show_progress:
            print(color(f"\r  [{total}/{total}] files scanned.      ", GREY), file=sys.stderr)
    else:
        with ThreadPoolExecutor(max_workers=workers) as exe:
            futures = {
                exe.submit(scan_file, f, min_severity, high_entropy_scan, decode_base64): f
                for f in files
            }
            for fut in as_completed(futures):
                path = futures[fut]
                try:
                    findings.extend(fut.result())
                except Exception as exc:
                    print(color(f"[WARN] scan failed for {path}: {exc}", YELLOW),
                          file=sys.stderr)
                done += 1
                if show_progress and done % max(1, total // 20) == 0:
                    print(color(f"\r  [{done}/{total}] files scanned, "
                                f"{len(findings)} finding(s)…", GREY),
                          end="", file=sys.stderr)
        if show_progress:
            print(color(f"\r  [{total}/{total}] files scanned.      ", GREY), file=sys.stderr)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line))
    return findings


# ──────────────────────────────────────────────
# Output helpers
# ──────────────────────────────────────────────

def redact(secret: str) -> str:
    """Mask the secret, leaving only a small hint of its length."""
    if len(secret) <= 8:
        return "*" * len(secret)
    if len(secret) <= 16:
        return secret[:2] + "*" * (len(secret) - 4) + secret[-2:]
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def _summary_lines(findings: list[Finding]) -> list[str]:
    if not findings:
        return [color("\n✔  No secrets found.", GREEN)]
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    files_hit = len({f.file for f in findings})
    total = len(findings)
    lines = [color("\n── Summary ──────────────────────────────", BOLD)]
    lines.append(f"  Files with findings : {color(str(files_hit), YELLOW)}")
    lines.append(f"  Total findings      : {color(str(total), RED if total else GREEN)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = counts.get(sev, 0)
        if n:
            lines.append(f"    {sev:<10}  {n}")
    lines.append("")
    return lines


def format_text(findings: list[Finding], redact_secrets: bool = False) -> str:
    lines: list[str] = []
    if findings and not redact_secrets:
        lines.append(color("⚠  WARNING: secrets are shown IN FULL — do not share this output publicly.",
                           YELLOW + BOLD))
        lines.append("")

    current_file = None
    for f in findings:
        if f.file != current_file:
            current_file = f.file
            if current_file is not None:
                lines.append("")
            lines.append(color(f.file, BOLD + MAGENTA))

        sev_col = SEVERITY_COLOR.get(f.severity, "")
        sev_tag = color(f"[{f.severity}]", sev_col)
        rule_tag = color(f"[{f.rule}]", CYAN)
        secret_display = f.secret if not redact_secrets else redact(f.secret)

        lines.append(f"  {color(str(f.line), GREY)}  {sev_tag} {rule_tag}  "
                     f"entropy={color(str(f.entropy), GREY)}")
        lines.append(f"       secret : {color(secret_display, YELLOW)}")
        lines.append(f"       context: {color(f.context, GREY)}")

    lines.extend(_summary_lines(findings))
    return "\n".join(lines) + "\n"


def format_json(findings: list[Finding], redact_secrets: bool = False) -> str:
    data = [asdict(f) for f in findings]
    if redact_secrets:
        for item in data:
            item["secret"] = redact(item["secret"])
    return json.dumps(data, indent=2)


def format_sarif(findings: list[Finding], redact_secrets: bool = False) -> str:
    rules_index: dict[str, int] = {}
    rules_list: list[dict] = []
    for f in findings:
        if f.rule not in rules_index:
            rules_index[f.rule] = len(rules_list)
            rules_list.append({
                "id": f.rule,
                "name": f.rule,
                "shortDescription": {"text": f"Detects {f.rule}."},
                "defaultConfiguration": {
                    "level": SEVERITY_SARIF_LEVEL.get(f.severity, "warning"),
                },
            })

    results = []
    for f in findings:
        secret_value = redact(f.secret) if redact_secrets else f.secret
        results.append({
            "ruleId": f.rule,
            "ruleIndex": rules_index[f.rule],
            "level": SEVERITY_SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"Potential {f.rule} exposed."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {
                        "startLine": f.line,
                        "endLine": f.line,
                        "snippet": {"text": f.context[:200]},
                    },
                },
                "properties": {"secret": secret_value, "entropy": f.entropy},
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "syck",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/RA000WL/secretsyoucantkeep",
                    "rules": rules_list,
                },
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _md_escape(value: str) -> str:
    return value.replace("|", r"\|").replace("\n", " ").replace("\r", " ")


def format_markdown(findings: list[Finding], redact_secrets: bool = False) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = [f"# syck scan report", f"_Generated: {ts}_", ""]

    if not findings:
        lines.append("**No secrets found.**")
        return "\n".join(lines) + "\n"

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    files_hit = len({f.file for f in findings})

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Files with findings:** {files_hit}")
    lines.append(f"- **Total findings:** {len(findings)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = counts.get(sev, 0)
        if n:
            lines.append(f"- **{sev}:** {n}")
    lines.append("")

    if not redact_secrets:
        lines.append("> ⚠️ **WARNING:** secrets below are shown IN FULL. Do not paste this report "
                     "into a public issue tracker without redacting first.")
        lines.append("")

    files: dict[str, list[Finding]] = {}
    for f in findings:
        files.setdefault(f.file, []).append(f)

    lines.append("## Findings")
    lines.append("")
    for path, items in files.items():
        lines.append(f"### `{_md_escape(path)}`")
        lines.append("")
        lines.append("| Line | Severity | Rule | Secret | Entropy |")
        lines.append("|------|----------|------|--------|---------|")
        for f in items:
            secret = (f"`{_md_escape(f.secret)}`" if not redact_secrets
                      else f"`{_md_escape(redact(f.secret))}`")
            lines.append(f"| {f.line} | {f.severity} | {f.rule} | {secret} | {f.entropy} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def format_csv(findings: list[Finding], redact_secrets: bool = False) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["file", "line", "rule", "severity", "secret", "context", "entropy"])
    for f in findings:
        secret = redact(f.secret) if redact_secrets else f.secret
        writer.writerow([f.file, f.line, f.rule, f.severity, secret, f.context, f.entropy])
    return buf.getvalue()


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>syck report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          margin: 24px; background: #0d1117; color: #c9d1d9; }}
  h1, h2, h3 {{ color: #f0f6fc; }}
  .meta {{ color: #8b949e; font-size: 0.9em; }}
  .warn {{ background: #2d1b00; border-left: 4px solid #d29922; padding: 10px 14px;
           border-radius: 4px; margin: 12px 0; color: #f0c674; }}
  .summary {{ display: flex; gap: 12px; margin: 16px 0; flex-wrap: wrap; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px;
           padding: 10px 14px; font-size: 0.95em; }}
  .CRITICAL {{ color: #f85149; font-weight: 700; }}
  .HIGH     {{ color: #d29922; font-weight: 600; }}
  .MEDIUM   {{ color: #58a6ff; }}
  .LOW      {{ color: #8b949e; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #21262d;
            font-size: 0.9em; vertical-align: top; }}
  th {{ background: #161b22; color: #f0f6fc; cursor: pointer; user-select: none; }}
  tr:hover td {{ background: #161b22; }}
  code {{ background: #161b22; padding: 2px 6px; border-radius: 4px;
          font-family: "SF Mono", Menlo, Consolas, monospace; word-break: break-all;
          color: #ffa657; }}
  details {{ margin: 8px 0; background: #0d1117; }}
  summary {{ cursor: pointer; padding: 10px 12px; background: #161b22;
             border: 1px solid #30363d; border-radius: 6px; font-weight: 500; }}
  summary:hover {{ background: #1c2128; }}
  .file-name {{ color: #d2a8ff; font-family: "SF Mono", Menlo, monospace; }}
  .context {{ color: #8b949e; font-style: italic; word-break: break-word; }}
  .empty {{ padding: 60px; text-align: center; color: #3fb950; font-size: 1.2em; }}
</style>
</head>
<body>
<h1>syck report</h1>
<p class="meta">Generated: {timestamp} &middot; Tool: syck v2.0.0</p>
{warning}
{body}
</body>
</html>
"""


def format_html(findings: list[Finding], redact_secrets: bool = False) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    warning = ""
    if findings and not redact_secrets:
        warning = ('<div class="warn">⚠ <strong>WARNING:</strong> secrets below are shown IN FULL. '
                   'Do not share this HTML file publicly.</div>')

    if not findings:
        body = '<div class="empty">✔ No secrets found.</div>'
    else:
        files: dict[str, list[Finding]] = {}
        for f in findings:
            files.setdefault(f.file, []).append(f)

        parts: list[str] = ['<div class="summary">']
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = counts[sev]
            parts.append(f'<div class="card {sev}">{sev}: {n}</div>')
        parts.append(f'<div class="card">Files: {len(files)}</div>')
        parts.append(f'<div class="card">Total: {len(findings)}</div>')
        parts.append('</div>')

        for path, items in files.items():
            parts.append('<details open>')
            parts.append(
                f'<summary><span class="file-name">{html_escape(path)}</span> '
                f'<span class="meta">({len(items)} finding{"s" if len(items) != 1 else ""})</span></summary>'
            )
            parts.append('<table>')
            parts.append('<thead><tr><th>Line</th><th>Severity</th><th>Rule</th>'
                         '<th>Secret</th><th>Entropy</th><th>Context</th></tr></thead>')
            parts.append('<tbody>')
            for f in items:
                secret_disp = (f.secret if not redact_secrets else redact(f.secret))
                parts.append(
                    f'<tr>'
                    f'<td>{f.line}</td>'
                    f'<td class="{f.severity}">{f.severity}</td>'
                    f'<td>{html_escape(f.rule)}</td>'
                    f'<td><code>{html_escape(secret_disp)}</code></td>'
                    f'<td>{f.entropy}</td>'
                    f'<td class="context">{html_escape(f.context)}</td>'
                    f'</tr>'
                )
            parts.append('</tbody></table>')
            parts.append('</details>')
        body = "\n".join(parts)

    return _HTML_TEMPLATE.format(timestamp=timestamp, warning=warning, body=body)


FORMATTERS = {
    "text":     format_text,
    "json":     format_json,
    "sarif":    format_sarif,
    "markdown": format_markdown,
    "csv":      format_csv,
    "html":     format_html,
}


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

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
  •  Run on a fresh target repo:    %(prog)s ./repo --severity CRITICAL
  •  Generate a clean report:        %(prog)s ./repo --format html -o r.html
  •  Upload to GitHub code scanning: %(prog)s ./repo --format sarif --redact \\
                                       -o results.sarif
  •  Scan JS/TS build artefacts:     %(prog)s ./dist --max-file-size 50M
  •  Skip noisy dirs:                %(prog)s ./repo --exclude 'test|mock|spec'
  •  CI gate (fail on CRITICAL only):
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
    p.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   default="LOW", help="Minimum severity to report (default: LOW)")
    p.add_argument("--format", choices=list(FORMATTERS.keys()),
                   default="text", help="Output format (default: text)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write output to FILE instead of stdout")
    p.add_argument("--redact", action="store_true",
                   help="Mask secret values in the output (default: shown in full)")
    p.add_argument("--show-secrets", action="store_true",
                   help=argparse.SUPPRESS)  # deprecated: secrets are now shown by default
    p.add_argument("--no-entropy", action="store_true",
                   help="Disable high-entropy token sweep")
    p.add_argument("--decode-base64", action="store_true",
                   help="Decode base64 strings and re-scan for secrets")
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
    p.add_argument("--config", metavar="FILE",
                   help="Path to config file (default: ./.syckrc, "
                        "~/.config/syck/config.json)")
    p.add_argument("--progress", action="store_true",
                   help="Print a one-line progress message to stderr")
    p.add_argument("--list-rules", action="store_true",
                   help="Print all built-in rules and exit")
    return p


# ──────────────────────────────────────────────
# Config file support
# ──────────────────────────────────────────────

_CONFIG_SEARCH_PATHS = [
    "~/.config/syck/config.json",
    "~/.syckrc",
    ".syckrc",
    ".syckrc.json",
]


def _load_config(cli_namespace) -> dict:
    """Load config files from well-known paths and merge them.

    Returns a dict keyed by argparse *dest* names (dashes → underscores).
    Priority (lowest → highest):

      1. ``~/.config/syck/config.json``
      2. ``~/.syckrc``
      3. ``./.syckrc`` / ``./.syckrc.json``
      4. ``--config`` (explicit)
    """
    config: dict = {}

    paths: list[Path] = []
    for p in _CONFIG_SEARCH_PATHS:
        resolved = Path(p).expanduser()
        if resolved not in paths:
            paths.append(resolved)
    if cli_namespace and getattr(cli_namespace, "config", None):
        paths.append(Path(cli_namespace.config))

    for path in paths:
        if not path.exists() or path.is_dir():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        normalized = {k.replace("-", "_").replace(" ", "_"): v for k, v in data.items()}
        config.update(normalized)

    return config


def main(argv: list[str]) -> int:
    global USE_COLOR

    parser = build_parser()

    # First pass: detect --config before full parse
    known, _ = parser.parse_known_args(argv)

    # Load config and bake it in as defaults
    cfg = _load_config(known)
    if cfg:
        parser.set_defaults(**cfg)

    args = parser.parse_args(argv)

    if args.no_color or args.format != "text":
        USE_COLOR = False

    # Load custom rules early — both --list-rules and --scan need them
    if args.rules:
        custom_rules = load_custom_rules(args.rules)
        if args.rules_only:
            RULES.clear()
            _RULE_RANK.clear()
        RULES.extend(custom_rules)
        for r in custom_rules:
            _RULE_RANK[r.name] = SEVERITY_ORDER[r.severity]

    if args.list_rules:
        print(f"{'Rule':<35} {'Severity':<10} Pattern")
        print("-" * 90)
        for rule in RULES:
            print(f"{rule.name:<35} {rule.severity:<10} {rule.pattern.pattern[:45]}")
        if args.rules_only:
            print("\n(Built-in rules excluded via --rules-only)")
        return 0

    # Split local paths from URLs.  URLs get downloaded to a temp dir
    # and the dir is added to the targets list — scan_paths treats
    # dirs and files uniformly.  The temp dir is cleaned up below.
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
        for u in urls:
            fetched = _fetch_url(u, temp_dir)
            if fetched is not None:
                targets.append(fetched)

    try:
        # Merge --exclude-file patterns into --exclude list
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
            exclude_patterns=exclude_patterns,
            workers=max(1, args.workers),
            max_file_size=args.max_file_size,
            progress=args.progress,
        )
    finally:
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)

    formatter = FORMATTERS[args.format]
    if args.format == "text":
        # Stream the formatted text directly to the chosen sink while preserving
        # ANSI colour codes captured in the returned string.
        output_text = formatter(findings, redact_secrets)
    else:
        output_text = formatter(findings, redact_secrets)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(output_text, encoding="utf-8")
        if USE_COLOR:
            print(color(f"Results written to {out_path}", GREEN))
    else:
        print(output_text, end="")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
