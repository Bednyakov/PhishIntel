"""Bounded same-site crawler that extracts publicly exposed contact data."""
from __future__ import annotations

import html
import ipaddress
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from http import cookiejar
from typing import Any

from .common import normalize_target

_MAX_PAGES = 500
_MAX_DEPTH = 8
_MAX_BYTES = 2_000_000
_USER_AGENT = "phishintel/1.0 resource-contact-parser"
_EMAIL = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}", re.I)
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().\-]{6,}\d)(?!\w)")
_BTC = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b", re.I)
_EVM = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_TRON = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
_SOLANA = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])")
_ADDRESS_HINT = re.compile(r"(?i)\b(?:address|адрес|street|ул\.?|улица|avenue|road|г\.?|город|zip|индекс)\b")


def _base_domain(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _allowed_host(host: str, root: str) -> bool:
    host = host.rstrip(".").lower()
    root = root.rstrip(".").lower()
    return host == root or host.endswith("." + root)


def _safe_url(url: str, root: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not _allowed_host(parsed.hostname, root):
        return False
    try:
        address = ipaddress.ip_address(parsed.hostname)
        return not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved)
    except ValueError:
        return True


def _normalize_url(value: str, parent: str, root: str) -> str | None:
    url = urllib.parse.urldefrag(urllib.parse.urljoin(parent, html.unescape(value.strip())))[0]
    parsed = urllib.parse.urlparse(url)
    if not parsed.hostname or not _safe_url(url, root):
        return None
    path = parsed.path or "/"
    if path.lower().endswith(('.pdf', '.zip', '.rar', '.7z', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.mp4', '.mp3', '.doc', '.docx', '.xls', '.xlsx')):
        return None
    return urllib.parse.urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", parsed.query, ""))


def _fetch(url: str, timeout: float) -> tuple[int, str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "text/html,application/xhtml+xml"})
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        payload = response.read(_MAX_BYTES + 1)
        return response.status, response.headers.get("content-type", ""), payload.decode(response.headers.get_content_charset() or "utf-8", errors="replace")


def _unique(values: list[str]) -> list[str]:
    return sorted(set(values), key=str.casefold)


def _extract(text: str) -> dict[str, list[str]]:
    visible = re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", text)
    visible = re.sub(r"(?s)<[^>]+>", " ", visible)
    visible = html.unescape(visible)
    emails = _unique(_EMAIL.findall(text))
    phones = _unique(re.sub(r"\s+", " ", item).strip(" .,-") for item in _PHONE.findall(visible))
    wallets = _unique(_BTC.findall(text) + _EVM.findall(text) + _TRON.findall(text) + _SOLANA.findall(text))
    addresses = []
    for line in re.split(r"[\n\r]+", visible):
        line = re.sub(r"\s+", " ", line).strip(" \t,;|")
        if line and _ADDRESS_HINT.search(line) and 10 <= len(line) <= 240:
            addresses.append(line)
    return {"emails": emails, "phones": phones, "wallets": wallets, "addresses": _unique(addresses)}


def analyze(target: str, timeout: float = 8.0, max_pages: int = _MAX_PAGES, max_depth: int = _MAX_DEPTH, progress_callback: Any = None) -> dict[str, Any]:
    host, root_url = normalize_target(target)
    root = _base_domain(host)
    start = root_url if urllib.parse.urlparse(root_url).scheme in {"http", "https"} else f"https://{host}/"
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    visited: set[str] = set()
    pages: list[dict[str, Any]] = []
    found = {"emails": [], "phones": [], "wallets": [], "addresses": []}
    errors: list[dict[str, str]] = []
    while queue and len(visited) < max(1, min(max_pages, _MAX_PAGES)):
        url, depth = queue.popleft()
        if url in visited or depth > max_depth or not _safe_url(url, root):
            continue
        visited.add(url)
        try:
            status, content_type, body = _fetch(url, timeout)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            errors.append({"url": url, "error": str(exc)})
            continue
        page = {"url": url, "depth": depth, "status_code": status, "content_type": content_type}
        if "html" not in content_type.lower() and not body.lstrip().lower().startswith(("<!doctype html", "<html")):
            page["skipped"] = "non_html"
            pages.append(page)
            continue
        extracted = _extract(body)
        page["contacts"] = extracted
        pages.append(page)
        for key in found:
            found[key].extend(extracted[key])
        if depth < max_depth:
            for link in re.findall(r"(?is)(?:href|src)\s*=\s*[\"']([^\"']+)", body):
                normalized = _normalize_url(link, url, root)
                if normalized and normalized not in visited:
                    queue.append((normalized, depth + 1))
        if progress_callback:
            progress_callback({"completed": len(visited), "queued": len(queue), "pages": max_pages})
    return {"tool": "resource-parser", "target": target.strip(), "root_domain": root, "summary": {"pages_visited": len(visited), "pages_with_contacts": sum(1 for page in pages if page.get("contacts")), "subdomains_seen": sorted({urllib.parse.urlparse(page["url"]).hostname for page in pages if urllib.parse.urlparse(page["url"]).hostname}), "limits": {"max_pages": max_pages, "max_depth": max_depth}}, "contacts": {key: _unique(values) for key, values in found.items()}, "pages": pages, "errors": errors}