"""syck.async_fetch — Concurrent URL fetching + SQLite content cache for syck.

Uses aiohttp when available for true async I/O,
falls back to ThreadPoolExecutor + urllib.
"""
from syck.async_fetch.cache import URLContentCache
from syck.async_fetch.fetcher import (
    _CACHE_TTL, _content_type_acceptable, _fetch_url_sync, _safe_name,
    fetch_urls_async, fetch_urls_threaded,
)

__all__ = [
    "URLContentCache",
    "_CACHE_TTL",
    "_content_type_acceptable",
    "_fetch_url_sync",
    "_safe_name",
    "fetch_urls_async",
    "fetch_urls_threaded",
]
