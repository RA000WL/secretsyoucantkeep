"""
syck_validate.py — Validate found secrets against provider APIs.

Zero dependencies — uses urllib only (matching syck.py's approach).
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass
class ValidationResult:
    rule: str
    secret: str
    valid: bool
    detail: str


def _fetch(url: str, headers: dict[str, str] | None = None,
           data: bytes | None = None, timeout: int = 8,
           auth: tuple[str, str] | None = None) -> tuple[int, str | dict]:
    req = urllib.request.Request(url, data=data, headers=headers or {})
    if auth:
        import base64
        creds = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, body
    except Exception as e:
        return 0, str(e)


def validate_github_pat(secret: str) -> ValidationResult:
    status, data = _fetch(
        "https://api.github.com/user",
        headers={"Authorization": f"token {secret}"},
    )
    if status == 200 and isinstance(data, dict):
        login = data.get("login", "unknown")
        return ValidationResult("github_pat", secret, True, f"login: {login}")
    return ValidationResult("github_pat", secret, False, f"HTTP {status}")


def validate_stripe_secret(secret: str) -> ValidationResult:
    import base64
    raw = base64.b64encode(f"{secret}:".encode()).decode()
    status, data = _fetch(
        "https://api.stripe.com/v1/account",
        headers={"Authorization": f"Basic {raw}"},
    )
    if status == 200 and isinstance(data, dict):
        email = data.get("email", "")
        return ValidationResult("stripe_secret_key", secret, True, email)
    return ValidationResult("stripe_secret_key", secret, False, f"HTTP {status}")


def validate_slack_token(secret: str) -> ValidationResult:
    status, data = _fetch(
        "https://slack.com/api/auth.test",
        headers={"Authorization": f"Bearer {secret}"},
    )
    if status == 200 and isinstance(data, dict) and data.get("ok"):
        return ValidationResult("slack_token", secret, True,
                                f"team: {data.get('team')}, user: {data.get('user')}")
    err = data.get("error", "") if isinstance(data, dict) else f"HTTP {status}"
    return ValidationResult("slack_token", secret, False, err)


def validate_sendgrid(secret: str) -> ValidationResult:
    status, _ = _fetch(
        "https://api.sendgrid.com/v3/user/profile",
        headers={"Authorization": f"Bearer {secret}"},
    )
    return ValidationResult("sendgrid_api_key", secret, status == 200, f"HTTP {status}")


def validate_anthropic_key(secret: str) -> ValidationResult:
    status, _ = _fetch(
        "https://api.anthropic.com/v1/models",
        headers={"x-api-key": secret, "anthropic-version": "2023-06-01"},
    )
    return ValidationResult("anthropic_api_key", secret, status == 200, f"HTTP {status}")


def validate_openai_key(secret: str) -> ValidationResult:
    status, _ = _fetch(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {secret}"},
    )
    return ValidationResult("openai_api_key", secret, status == 200, f"HTTP {status}")


def validate_google_api_key(secret: str) -> ValidationResult:
    status, data = _fetch(
        f"https://www.googleapis.com/customsearch/v1?key={secret}&q=test&cx=000000000000000000000:aaaaaaaaaaa",
    )
    valid = status == 200 and (isinstance(data, dict) and "error" not in data)
    return ValidationResult("google_api_key", secret, valid, f"HTTP {status}")


def validate_huggingface_token(secret: str) -> ValidationResult:
    status, data = _fetch(
        "https://huggingface.co/api/whoami-v2",
        headers={"Authorization": f"Bearer {secret}"},
    )
    if status == 200 and isinstance(data, dict):
        name = data.get("name", "unknown")
        return ValidationResult("huggingface_token", secret, True, f"user: {name}")
    return ValidationResult("huggingface_token", secret, False, f"HTTP {status}")


def validate_gitlab_pat(secret: str) -> ValidationResult:
    status, data = _fetch(
        "https://gitlab.com/api/v4/user",
        headers={"PRIVATE-TOKEN": secret},
    )
    if status == 200 and isinstance(data, dict):
        username = data.get("username", "unknown")
        return ValidationResult("gitlab_pat", secret, True, f"user: {username}")
    return ValidationResult("gitlab_pat", secret, False, f"HTTP {status}")


def validate_gitlab_ci_job_token(secret: str) -> ValidationResult:
    status, data = _fetch(
        "https://gitlab.com/api/v4/user",
        headers={"JOB-TOKEN": secret},
    )
    return ValidationResult("gitlab_ci_job_token", secret, status == 200, f"HTTP {status}")


def validate_gitlab_pipeline_trigger(secret: str) -> ValidationResult:
    status, _ = _fetch(
        "https://gitlab.com/api/v4/projects",
        headers={"PRIVATE-TOKEN": secret},
    )
    return ValidationResult("gitlab_pipeline_trigger", secret, status == 200, f"HTTP {status}")


def validate_perplexity_api_key(secret: str) -> ValidationResult:
    status, _ = _fetch(
        "https://api.perplexity.ai/chat/completions",
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
        },
        data=json.dumps({
            "model": "llama-3.1-8b-instruct",
            "messages": [{"role": "user", "content": "test"}],
            "max_tokens": 1,
        }).encode(),
    )
    return ValidationResult("perplexity_api_key", secret, status == 200, f"HTTP {status}")


def validate_slack_webhook(secret: str) -> ValidationResult:
    status, _ = _fetch(
        secret,
        data=json.dumps({"text": "syck validation test"}).encode(),
    )
    return ValidationResult("slack_webhook", secret, status == 200, f"HTTP {status}")


def validate_discord_bot_token(secret: str) -> ValidationResult:
    status, data = _fetch(
        "https://discord.com/api/v10/users/@me",
        headers={"Authorization": f"Bot {secret}"},
    )
    if status == 200 and isinstance(data, dict):
        uid = data.get("id", "unknown")
        return ValidationResult("discord_bot_token", secret, True, f"bot_id: {uid}")
    err = data.get("message", "") if isinstance(data, dict) else f"HTTP {status}"
    return ValidationResult("discord_bot_token", secret, False, err)


def validate_aws_sts(secret: str) -> ValidationResult:
    # AWS GetCallerIdentity requires a signed request.
    # Without the paired secret key we can only call a public endpoint.
    # Use iam.amazonaws.com?Action=GetUser with the access key in the
    # Authorization header (AWS4-HMAC-SHA256).  Since we lack the secret
    # key, mark as "requires key pair" but attempt a lightweight check.
    return ValidationResult("aws_access_key_id", secret, False,
                            "requires access_key + secret_key pair for API validation")


# Dispatch map: rule name → validator function
VALIDATORS = {
    "github_pat":           lambda s: validate_github_pat(s),
    "github_server_token":  lambda s: validate_github_pat(s),
    "github_oauth":         lambda s: validate_github_pat(s),
    "github_app_token":     lambda s: validate_github_pat(s),
    "github_fine_grained_pat": lambda s: validate_github_pat(s),
    "stripe_secret_key":    lambda s: validate_stripe_secret(s),
    "slack_token":          lambda s: validate_slack_token(s),
    "slack_webhook":        lambda s: validate_slack_webhook(s),
    "sendgrid_api_key":     lambda s: validate_sendgrid(s),
    "anthropic_api_key":    lambda s: validate_anthropic_key(s),
    "openai_api_key":       lambda s: validate_openai_key(s),
    "openai_project_key":   lambda s: validate_openai_key(s),
    "google_api_key":       lambda s: validate_google_api_key(s),
    "huggingface_token":    lambda s: validate_huggingface_token(s),
    "gitlab_pat":           lambda s: validate_gitlab_pat(s),
    "gitlab_ci_job_token":  lambda s: validate_gitlab_ci_job_token(s),
    "gitlab_pipeline_trigger": lambda s: validate_gitlab_pipeline_trigger(s),
    "perplexity_api_key":   lambda s: validate_perplexity_api_key(s),
    "aws_access_key_id":    lambda s: validate_aws_sts(s),
    "discord_bot_token":    lambda s: validate_discord_bot_token(s),
}


def validate_findings(findings: list, workers: int = 5) -> dict:
    """
    Run validators against findings that have a matching rule.
    Returns dict keyed by (rule, secret[:40]) → ValidationResult.
    """
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

    if not tasks:
        return {}

    print(f"[*] validating {len(tasks)} secret(s) against provider APIs…", file=sys.stderr)

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
