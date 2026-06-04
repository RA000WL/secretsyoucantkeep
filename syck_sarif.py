"""
syck_sarif.py — Upload SARIF results to GitHub Code Scanning API.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request


def upload_sarif(sarif_path: str, repo: str, token: str,
                 timeout: int = 30) -> bool:
    """Upload a SARIF file to GitHub Code Scanning API.

    Args:
        sarif_path: Path to the .sarif file.
        repo: GitHub repository (owner/name).
        token: GitHub token with 'security_events' write scope.
        timeout: Request timeout in seconds.

    Returns:
        True on success, False otherwise.
    """
    if not sarif_path or not repo or not token:
        return False

    try:
        with open(sarif_path, encoding="utf-8") as f:
            sarif_data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] failed to read SARIF file: {e}", file=sys.stderr)
        return False

    # The API expects the SARIF payload base64-encoded
    import base64
    sarif_bytes = json.dumps(sarif_data).encode("utf-8")
    sarif_b64 = base64.b64encode(sarif_bytes).decode("ascii")

    payload = {
        "commit_sha": _get_head_sha(),
        "ref": _get_ref(),
        "sarif": sarif_b64,
        "tool_name": "syck",
        "checkout_uri": f"https://github.com/{repo}",
    }

    url = f"https://api.github.com/repos/{repo}/code-scanning/sarifs"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                if resp.status == 202:
                    result = json.loads(body)
                    analysis_url = result.get("url", "")
                    print(f"[+] SARIF uploaded: {analysis_url}", file=sys.stderr)
                    return True
                elif resp.status == 401:
                    print("[!] SARIF upload failed: bad token", file=sys.stderr)
                    return False
                else:
                    print(f"[!] SARIF upload failed: HTTP {resp.status}", file=sys.stderr)
                    return False
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = int(e.headers.get("Retry-After", str(2 ** attempt)))
                time.sleep(wait)
                continue
            body = e.read().decode("utf-8", errors="replace")[:500]
            print(f"[!] SARIF upload HTTP {e.code}: {body}", file=sys.stderr)
            return False
        except (urllib.error.URLError, OSError) as e:
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            print(f"[!] SARIF upload error: {e}", file=sys.stderr)
            return False

    return False


def _get_head_sha() -> str:
    import subprocess
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return ""


def _get_ref() -> str:
    ref = _env_or_git("GITHUB_REF", "git symbolic-ref HEAD")
    return ref or "refs/heads/main"


def _env_or_git(env_var: str, git_cmd: str) -> str:
    import os
    import subprocess
    val = os.environ.get(env_var)
    if val:
        return val
    try:
        result = subprocess.run(
            git_cmd.split(), capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return ""
