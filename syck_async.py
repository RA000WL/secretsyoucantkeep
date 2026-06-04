#!/usr/bin/env python3
"""syck_async.py — backcompat shim for syck/async_fetch/ package."""
from syck.async_fetch import (
    URLContentCache, _CACHE_TTL, _content_type_acceptable,
    _fetch_url_sync, _safe_name, fetch_urls_async, fetch_urls_threaded,
)
