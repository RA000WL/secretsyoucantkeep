"""URL fetcher functions (sync threaded + async aiohttp)."""
from __future__ import annotations

import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from syck.async_fetch.cache import URLContentCache, _CACHE_TTL

__all__ = [
    "_CACHE_TTL",
    "_content_type_acceptable",
    "_fetch_url_sync",
    "_safe_name",
    "fetch_urls_async",
    "fetch_urls_threaded",
]

_ACCEPTED_CT = re.compile(
    r"(?i)(text/|application/javascript|application/json|"
    r"application/x-javascript|application/ecmascript)"
)


def _content_type_acceptable(url: str, timeout: int = 10) -> bool:
    """Send a HEAD request and check Content-Type.  Non-fatal errors
    return True so the caller still attempts the GET."""
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "syck/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
        return bool(_ACCEPTED_CT.search(ct)) if ct else True
    except Exception:
        return True


_COLOR_MAP = {"reset": "\033[0m", "grey": "\033[90m", "green": "\033[92m",
              "yellow": "\033[93m", "cyan": "\033[96m"}


def _safe_name(url: str) -> str:
    last = url.split("?", 1)[0].rsplit("/", 1)[-1] or "index.html"
    name = "".join(c for c in last if c.isalnum() or c in "._-")
    if not name:
        name = "index.html"
    return name[:80]


def _color(text: str, code: str) -> str:
    return f"{_COLOR_MAP.get(code, '')}{text}{_COLOR_MAP['reset']}" if sys.stdout.isatty() else text


def _fetch_url_sync(url: str, dest_dir: Path, timeout: int = 20,
                    cache: URLContentCache | None = None,
                    filter_ct: bool = False) -> Path | None:
    name = _safe_name(url)
    dest = dest_dir / name
    i = 1
    while dest.exists():
        stem, suf = dest.stem, dest.suffix
        dest = dest_dir / f"{stem}_{i}{suf}"
        i += 1

    if filter_ct and not _content_type_acceptable(url):
        return None

    if cache is not None:
        cached = cache.get(url)
        if cached is not None:
            content, _ = cached
            dest.write_bytes(content)
            return dest

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "syck/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        if not data:
            return None
        dest.write_bytes(data)
        if cache is not None:
            ct = resp.headers.get("Content-Type", "")
            cache.put(url, data, ct)
        return dest
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"  [!] failed {url}: {exc}", file=sys.stderr)
        return None


def fetch_urls_threaded(urls: list[str], dest_dir: Path,
                        workers: int = 10, timeout: int = 20,
                        cache: URLContentCache | None = None,
                        filter_content_type: bool = False) -> list[Path]:
    results: list[Path] = []
    with ThreadPoolExecutor(max_workers=workers) as exe:
        futs = {exe.submit(_fetch_url_sync, u, dest_dir, timeout,
                           cache, filter_content_type): u for u in urls}
        for fut in as_completed(futs):
            result = fut.result()
            if result is not None:
                results.append(result)
    return results


try:
    import aiohttp
    import asyncio

    async def _fetch_one_async(session: aiohttp.ClientSession, url: str,
                               dest_dir: Path, sem: asyncio.Semaphore,
                               cache: URLContentCache | None = None,
                               filter_ct: bool = False) -> Path | None:
        async with sem:
            name = _safe_name(url)
            dest = dest_dir / name
            i = 1
            while dest.exists():
                stem, suf = dest.stem, dest.suffix
                dest = dest_dir / f"{stem}_{i}{suf}"
                i += 1

            if filter_ct and not _content_type_acceptable(url):
                return None

            if cache is not None:
                cached = cache.get(url)
                if cached is not None:
                    content, _ = cached
                    dest.write_bytes(content)
                    return dest

            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=20)
                ) as resp:
                    data = await resp.read()
                if not data:
                    return None
                dest.write_bytes(data)
                if cache is not None:
                    ct = resp.headers.get("Content-Type", "")
                    cache.put(url, data, ct)
                return dest
            except Exception as exc:
                print(f"  [!] failed {url}: {exc}", file=sys.stderr)
                return None

    async def _fetch_all_async(urls: list[str], dest_dir: Path,
                               max_concurrent: int = 10,
                               cache: URLContentCache | None = None,
                               filter_ct: bool = False) -> list[Path]:
        connector = aiohttp.TCPConnector(limit=max_concurrent)
        sem = asyncio.Semaphore(max_concurrent)
        async with aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": "syck/2.0"},
        ) as session:
            tasks = [_fetch_one_async(session, u, dest_dir, sem, cache, filter_ct)
                     for u in urls]
            results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    def fetch_urls_async(urls: list[str], dest_dir: Path,
                         max_concurrent: int = 10,
                         cache: URLContentCache | None = None,
                         filter_content_type: bool = False) -> list[Path]:
        """Fetch URLs concurrently using aiohttp (async I/O).

        Parameters
        ----------
        urls : list[str]
            URLs to fetch.
        dest_dir : Path
            Directory to write downloaded files.
        max_concurrent : int
            Max simultaneous connections.
        cache : URLContentCache | None
            Optional SQLite-backed cache for URL content.
        filter_content_type : bool
            Skip downloads whose HEAD Content-Type is not JS/HTML/JSON.

        Returns
        -------
        list[Path]
            Paths of successfully downloaded files.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None and loop.is_running():
            return fetch_urls_threaded(urls, dest_dir,
                                       max_concurrent, cache=cache,
                                       filter_content_type=filter_content_type)
        return asyncio.run(
            _fetch_all_async(urls, dest_dir, max_concurrent, cache,
                             filter_ct=filter_content_type)
        )

except ImportError:
    def fetch_urls_async(urls: list[str], dest_dir: Path,
                         max_concurrent: int = 10,
                         cache: URLContentCache | None = None,
                         filter_content_type: bool = False) -> list[Path]:
        """Fallback: fetch URLs concurrently using threads (aiohttp not installed)."""
        print("[*] aiohttp not installed; using threaded fetcher "
              "(install aiohttp for 5-10x faster URL scanning)", file=sys.stderr)
        return fetch_urls_threaded(urls, dest_dir, max_concurrent,
                                   cache=cache,
                                   filter_content_type=filter_content_type)
