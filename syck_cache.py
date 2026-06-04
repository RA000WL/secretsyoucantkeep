"""
syck_cache.py — File content cache for syck scanner.

Caches scan results keyed by SHA256 content hash + min severity,
so unchanged files are not re-scanned on subsequent runs.

Cache directory: ./.syck-cache/ (configurable)
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path


MAX_AGE_DAYS = 14
CACHE_VERSION = 1


@dataclass
class CacheEntry:
    content_hash: str
    findings_json: str
    timestamp: float
    file_size: int
    min_severity: str
    cache_version: int = CACHE_VERSION


class SyckCache:
    def __init__(self, cache_dir: Path = Path(".syck-cache")):
        self.cache_dir = cache_dir

    def _content_hash(self, path: Path) -> str:
        h = hashlib.sha256()
        try:
            with path.open("rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()

    def _cache_path(self, content_hash: str) -> Path:
        return self.cache_dir / content_hash[:2] / f"{content_hash}.json"

    def get(self, path: Path, min_severity: str) -> list | None:
        content_hash = self._content_hash(path)
        if not content_hash:
            return None
        cache_path = self._cache_path(content_hash)
        if not cache_path.exists():
            return None
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            if data.get("cache_version") != CACHE_VERSION:
                return None
            if data.get("min_severity") != min_severity:
                return None
            if time.time() - data.get("timestamp", 0) > MAX_AGE_DAYS * 86400:
                cache_path.unlink(missing_ok=True)
                return None
            return json.loads(data["findings_json"])
        except Exception:
            return None

    def put(self, path: Path, findings: list, min_severity: str) -> None:
        try:
            content_hash = self._content_hash(path)
            if not content_hash:
                return
        except OSError:
            return
        cache_path = self._cache_path(content_hash)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        entry = CacheEntry(
            content_hash=content_hash,
            findings_json=json.dumps([asdict(f) for f in findings]),
            timestamp=time.time(),
            file_size=cache_path.stat().st_size if cache_path.exists() else 0,
            min_severity=min_severity,
        )
        tmp = cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(entry)), encoding="utf-8")
        tmp.rename(cache_path)

    def invalidate(self, path: Path) -> None:
        content_hash = self._content_hash(path)
        if not content_hash:
            return
        cache_path = self._cache_path(content_hash)
        if cache_path.exists():
            cache_path.unlink()

    def clear(self) -> int:
        count = 0
        if self.cache_dir.exists():
            for p in self.cache_dir.rglob("*.json"):
                p.unlink()
                count += 1
        return count

    def cleanup(self, max_age_days: int = MAX_AGE_DAYS) -> int:
        removed = 0
        cutoff = time.time() - max_age_days * 86400
        if not self.cache_dir.exists():
            return 0
        for p in self.cache_dir.rglob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if data.get("timestamp", 0) < cutoff:
                    p.unlink()
                    removed += 1
            except Exception:
                p.unlink(missing_ok=True)
                removed += 1
        # Remove empty directories
        for d in sorted(self.cache_dir.rglob("*"), key=lambda x: str(x), reverse=True):
            if d.is_dir() and not any(d.iterdir()):
                try:
                    d.rmdir()
                except OSError:
                    pass
        return removed
