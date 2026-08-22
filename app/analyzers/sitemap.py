"""Sitemap discovery and XML sitemap parsing."""

import ssl
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from .common import normalize_target, unavailable

_MAX_BYTES = 2_000_000
_MAX_URLS = 10_000
_MAX_SITEMAPS = 10
_MAX_WORKERS = 4
_USER_AGENT = "phishintel/1.0"


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _parse(payload: bytes) -> tuple[str, list[str]]:
    root = ET.fromstring(payload)
    kind = _local_name(root.tag)
    values = []
    for element in root.iter():
        if _local_name(element.tag) == "loc" and element.text and element.text.strip():
            values.append(element.text.strip())
    return kind, values


def _fetch(url: str, timeout: float) -> tuple[int, bytes, str]:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT}, method="GET")
    with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
        return response.status, response.read(_MAX_BYTES + 1), response.headers.get("content-type", "")


def _fetch_sitemaps(urls: list[str], timeout: float) -> list[tuple[str, tuple[int, bytes, str]]]:
    """Fetch a batch of sitemap files concurrently, preserving URL order."""
    if not urls:
        return []
    workers = min(_MAX_WORKERS, len(urls))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        responses = executor.map(lambda url: _fetch(url, timeout), urls)
        return list(zip(urls, responses))


def analyze(target: str, timeout: float = 8.0) -> dict:
    host, _ = normalize_target(target)
    root_url = f"https://{host}/sitemap.xml"
    queue = [root_url]
    visited = set()
    urls = set()
    discovered = []
    try:
        while queue and len(visited) < _MAX_SITEMAPS:
            batch = []
            while queue and len(visited) + len(batch) < _MAX_SITEMAPS:
                sitemap_url = queue.pop(0)
                if sitemap_url in visited or sitemap_url in batch:
                    continue
                batch.append(sitemap_url)
            visited.update(batch)

            # The first batch contains the root sitemap. Subsequent batches
            # contain children discovered in sitemap indexes and are fetched
            # concurrently by _fetch_sitemaps.
            fetched = _fetch_sitemaps(batch, timeout)
            for sitemap_url, (status_code, payload, content_type) in fetched:
                if len(payload) > _MAX_BYTES:
                    return {"status": "invalid", "url": root_url, "error": "sitemap exceeds size limit", "sitemaps": discovered, "urls": sorted(urls), "count": len(urls)}
                kind, locations = _parse(payload)
                discovered.append({"url": sitemap_url, "status_code": status_code, "content_type": content_type, "type": kind, "count": len(locations)})
                if kind == "sitemapindex":
                    queue.extend(url for url in locations if url not in visited)
                elif kind == "urlset":
                    urls.update(locations)
                else:
                    raise ValueError("unsupported XML root")
                if len(urls) >= _MAX_URLS:
                    urls = set(sorted(urls)[:_MAX_URLS])
                    queue.clear()
                    break
        return {"status": "ok", "url": root_url, "sitemaps": discovered, "urls": sorted(urls), "count": len(urls)}
    except urllib.error.HTTPError as exc:
        return {"status": "not_found" if exc.code == 404 else "unavailable", "url": root_url, "http_status": exc.code, "sitemaps": discovered, "urls": sorted(urls), "count": len(urls), "error": str(exc)}
    except (urllib.error.URLError, TimeoutError, OSError, ET.ParseError, ValueError) as exc:
        return {**unavailable(exc), "url": root_url, "sitemaps": discovered, "urls": sorted(urls), "count": len(urls)}