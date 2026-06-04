"""syck.hunt.utils — shared helpers for the syck-hunt pipeline."""
from __future__ import annotations

import shutil
import subprocess
import sys
import threading
import time

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
# Generic subprocess wrapper
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


# ──────────────────────────────────────────────
# Filename safety helper (shared by stages + recon)
# ──────────────────────────────────────────────

def _safe_name(url: str) -> str:
    last = url.split("?", 1)[0].rsplit("/", 1)[-1] or "index.html"
    name = "".join(c for c in last if c.isalnum() or c in "._-")
    if not name:
        return "index.html"
    return name[:80]


# ──────────────────────────────────────────────
# Checkpoint constants
# ──────────────────────────────────────────────

CHECKPOINT_FILE = "resume.json"
