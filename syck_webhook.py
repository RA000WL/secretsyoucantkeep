"""
syck_webhook.py — Send findings to webhook endpoints (Slack, Discord, JSON).
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from html import escape as html_escape


def send_webhooks(url: str, findings: list, fmt: str = "json",
                  redact: bool = False, timeout: int = 10) -> bool:
    """Post findings to a webhook URL.

    Args:
        url: Webhook URL.
        findings: List of Finding objects.
        fmt: Payload format — 'slack', 'discord', or 'json'.
        redact: Mask secret values.
        timeout: Request timeout.

    Returns:
        True on success.
    """
    payload = _build_payload(findings, fmt, redact)
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    for attempt in range(3):
        try:
            req = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status in (200, 201, 204):
                    return True
                return False
        except (urllib.error.URLError, OSError, ValueError) as exc:
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            print(f"[!] webhook failed: {exc}", file=sys.stderr)
    return False


def _redact(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    if len(secret) <= 16:
        return secret[:2] + "*" * (len(secret) - 4) + secret[-2:]
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]


def _build_payload(findings: list, fmt: str, redact: bool) -> dict:
    if fmt == "slack":
        return _build_slack(findings, redact)
    elif fmt == "discord":
        return _build_discord(findings, redact)
    else:
        return _build_json(findings, redact)


def _build_json(findings: list, redact: bool) -> dict:
    items = []
    for f in findings:
        items.append({
            "file": f.file,
            "line": f.line,
            "rule": f.rule,
            "severity": f.severity,
            "secret": _redact(f.secret) if redact else f.secret,
            "context": f.context,
            "entropy": f.entropy,
        })
    return {"findings": items, "total": len(items)}


def _build_slack(findings: list, redact: bool) -> dict:
    criticals = [f for f in findings if f.severity == "CRITICAL"]
    highs = [f for f in findings if f.severity == "HIGH"]
    others = [f for f in findings if f.severity not in ("CRITICAL", "HIGH")]

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🔑 syck scan results"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": (
                f"*{len(findings)}* finding(s) — "
                f"{len(criticals)} CRITICAL, {len(highs)} HIGH, {len(others)} other"
            )},
        },
        {"type": "divider"},
    ]

    for f in (criticals + highs)[:10]:
        secret = _redact(f.secret) if redact else f.secret
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": (
                f"*[{f.severity}]* `{f.rule}`\n"
                f"📄 `{f.file}:{f.line}`\n"
                f"🔐 `{html_escape(secret)[:200]}`"
            )},
        })

    if len(findings) > 10:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"… and {len(findings) - 10} more"}],
        })

    return {"blocks": blocks}


def _build_discord(findings: list, redact: bool) -> dict:
    color_map = {"CRITICAL": 15548997, "HIGH": 16753920,
                 "MEDIUM": 16740352, "LOW": 10181046, "INFO": 5763719}
    criticals = [f for f in findings if f.severity == "CRITICAL"]
    highs = [f for f in findings if f.severity == "HIGH"]

    embeds = []
    for f in (criticals + highs)[:10]:
        secret = _redact(f.secret) if redact else f.secret
        embeds.append({
            "title": f"[{f.severity}] {f.rule}",
            "color": color_map.get(f.severity, 10181046),
            "fields": [
                {"name": "File", "value": f"`{f.file}:{f.line}`", "inline": True},
                {"name": "Secret", "value": f"`{html_escape(secret)[:200]}`", "inline": False},
            ],
        })

    return {
        "username": "syck",
        "embeds": embeds,
        "content": f"**syck scan** — {len(findings)} finding(s) "
                   f"({len(criticals)} CRITICAL, {len(highs)} HIGH)",
    }
