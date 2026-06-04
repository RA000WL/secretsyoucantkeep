from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Iterable

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
GREY    = "\033[90m"
MAGENTA = "\033[95m"

USE_COLOR = True
DEBUG = False

_HAVE_TQDM: bool = False
try:
    from tqdm import tqdm as _tqdm
    _HAVE_TQDM = True
except ImportError:
    _tqdm = None


def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if USE_COLOR else text


def debug(msg: str) -> None:
    if DEBUG:
        print(color(f"[DEBUG] {msg}", GREY), file=sys.stderr)


SEVERITY_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     YELLOW + BOLD,
    "MEDIUM":   CYAN,
    "LOW":      GREY,
    "INFO":     GREEN,
}

SEVERITY_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "none",
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
    ".map",
}

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".mypy_cache", ".pytest_cache",
    "node_modules", "venv", ".venv", "__pycache__", "build",
    ".eggs", "target", "vendor",
}

DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024
DEFAULT_WORKERS = 4


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS or path.name in TEXT_EXTENSIONS:
        return True
    if path.name.startswith(".env."):
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
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=follow_symlinks):
                        if entry.name in SKIP_DIRS or entry.name.startswith("."):
                            continue
                        stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=follow_symlinks):
                        candidate = Path(entry.path)
                        if max_file_size:
                            try:
                                if entry.stat().st_size > max_file_size:
                                    continue
                            except OSError:
                                continue
                        if exclude_patterns:
                            rel = str(candidate)
                            if any(pat.search(rel) for pat in exclude_patterns):
                                continue
                        yield candidate
        except PermissionError:
            continue
