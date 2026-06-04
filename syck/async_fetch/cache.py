"""SQLite-backed URL content cache (24h TTL)."""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from pathlib import Path

_CACHE_TTL = 86400  # 24 hours


class URLContentCache:
    """SQLite-backed cache for URL content keyed by sha256(url).

    Stores raw bytes + content-type + timestamp so re-scans avoid
    re-fetching unchanged URLs within the TTL window.
    """

    def __init__(self, db_path: str | Path = ".syck-url-cache.sqlite"):
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    def _ensure(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS url_cache ("
                "  url_hash TEXT PRIMARY KEY,"
                "  url TEXT NOT NULL,"
                "  content BLOB,"
                "  content_type TEXT DEFAULT '',"
                "  timestamp REAL NOT NULL"
                ")"
            )
            self._conn.commit()
        return self._conn

    def get(self, url: str) -> tuple[bytes, str] | None:
        """Return (content_bytes, content_type) or None if missing/stale."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        with self._lock:
            cur = self._ensure().execute(
                "SELECT content, content_type, timestamp FROM url_cache "
                "WHERE url_hash = ?",
                (url_hash,),
            )
            row = cur.fetchone()
        if row and time.time() - row[2] < _CACHE_TTL:
            return row[0], row[1]
        return None

    def put(self, url: str, content: bytes, content_type: str = "") -> None:
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        with self._lock:
            self._ensure().execute(
                "INSERT OR REPLACE INTO url_cache VALUES (?, ?, ?, ?, ?)",
                (url_hash, url, content, content_type, time.time()),
            )
            self._ensure().commit()

    def clear(self) -> int:
        with self._lock:
            count = self._ensure().execute(
                "SELECT COUNT(*) FROM url_cache"
            ).fetchone()[0]
            self._ensure().execute("DELETE FROM url_cache")
            self._ensure().commit()
        return count

    def cleanup(self) -> int:
        cutoff = time.time() - _CACHE_TTL
        with self._lock:
            cur = self._ensure().execute(
                "DELETE FROM url_cache WHERE timestamp < ?", (cutoff,)
            )
            count = cur.rowcount
            self._ensure().commit()
        return count

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __del__(self) -> None:
        self.close()
