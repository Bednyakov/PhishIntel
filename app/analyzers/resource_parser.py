"""Bounded same-site crawler that extracts publicly exposed contact data."""
from __future__ import annotations

import html
import asyncio
import ipaddress
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from functools import partial
from http import cookiejar
from itertools import cycle
from typing import Any
from urllib.parse import parse_qsl

from ..config import list_value
from .common import host_url, normalize_target
from ..history import record as record_history
from . import content, dns, port_scan, rdap, redirects, subdomains, tls, whois

_MAX_PAGES = 500
_MAX_DEPTH = 8
_MAX_BYTES = 2_000_000
_USER_AGENT = "phishintel/1.0 resource-contact-parser"
_USER_AGENTS = "PHISHINTEL_RESOURCE_USER_AGENTS"
_PROXIES = "PHISHINTEL_RESOURCE_PROXIES"
_EMAIL = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}", re.I)
_PHONE_RU = re.compile(r"(?<![\d\w])(?:\+7|8)[\s(.-]*\d{3}[\s)./-]*\d{3}[\s.-]*\d{2}[\s.-]*\d{2}(?!\d)")
_PHONE_US = re.compile(r"(?<![\d\w])(?:\+?1[\s.-]*)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[\s.-]+\d{3}[\s.-]+\d{4}(?!\d)")
_BTC = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b", re.I)
_EVM = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_TRON = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
_SOLANA = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])")
_ADDRESS_HINT = re.compile(r"(?i)\b(?:address|адрес|street|st\.?|ул\.?|улица|avenue|ave\.?|road|rd\.?|boulevard|blvd\.?|drive|г\.?|город|zip|индекс)\b")
_PHONE_FIELD = re.compile(r"(?i)(?:^|[-_:\s])(phone|telephone|tel|mobile|моб|тел|телефон)(?:$|[-_:\s])")
_ADDRESS_FIELD = re.compile(r"(?i)(?:^|[-_:\s])(address|адрес|street|улица|city|город|postal|zip|индекс)(?:$|[-_:\s])")
_API_HINT = re.compile(r"(?i)(?:^|[/?._-])(api|graphql|rest|ajax|rpc)(?:[/?._-]|$)")
_SCRIPT = re.compile(r"(?is)<script\b([^>]*)>(.*?)</script\s*>")
_ATTR = re.compile(r"(?is)\b(?:href|src|action|data-url|data-api|content)\s*=\s*[\"']([^\"']+)")


def _base_domain(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _allowed_host(host: str, root: str) -> bool:
    host = host.rstrip(".").lower()
    root = root.rstrip(".").lower()
    try:
        return ipaddress.ip_address(host) == ipaddress.ip_address(root)
    except ValueError:
        pass
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
    raw_value = html.unescape(value.strip())
    if any(ord(char) < 32 or ord(char) == 127 for char in raw_value):
        return None
    url = urllib.parse.urldefrag(urllib.parse.urljoin(parent, raw_value))[0]
    parsed = urllib.parse.urlparse(url)
    if not parsed.hostname or not _safe_url(url, root):
        return None
    path = parsed.path or "/"
    if path.lower().endswith(('.pdf', '.zip', '.rar', '.7z', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.mp4', '.mp3', '.doc', '.docx', '.xls', '.xlsx')):
        return None
    # Sitemap and HTML producers sometimes emit spaces in slugs. Encode only
    # URL components, keeping the report readable while making urlopen safe.
    encoded_path = urllib.parse.quote(urllib.parse.unquote(path), safe="/%:@!$&'()*+,;=-._~")
    encoded_query = urllib.parse.quote(urllib.parse.unquote(parsed.query), safe="=&/?%:@!$'()*+,;=-._~")
    return urllib.parse.urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), encoded_path, "", encoded_query, ""))

def _fetch(url: str, timeout: float, user_agent: str = _USER_AGENT, proxy: str | None = None) -> tuple[int, str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": user_agent}, method="GET")
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(*handlers) if proxy else None
    opener_context = opener.open if opener is not None else urllib.request.urlopen
    with opener_context(request, timeout=timeout, context=context) as response:
        payload = response.read(_MAX_BYTES + 1)
        return response.status, response.headers.get("content-type", ""), payload.decode(response.headers.get_content_charset() or "utf-8", errors="replace")


def _unique(values: list[str]) -> list[str]:
    return sorted(set(values), key=str.casefold)


def _extract(text: str) -> dict[str, list[str]]:
    specialized_phone_values: list[str] = []
    specialized_address_values: list[str] = []
    for tag, attrs, value in re.findall(r"(?is)<([a-z][\w:-]*)\b([^>]*)>(.*?)</\1\s*>", text):
        field_names = " ".join(re.findall(r"(?i)(?:class|id|name|itemprop|aria-label|data-field)\s*=\s*[\"']([^\"']+)", attrs))
        plain_value = re.sub(r"(?s)<[^>]+>", " ", html.unescape(value)).strip()
        if not plain_value:
            continue
        if _PHONE_FIELD.search(field_names):
            specialized_phone_values.append(plain_value)
        tel_values = re.findall(r"(?i)href\s*=\s*[\"']tel:([^\"']+)", attrs)
        specialized_phone_values.extend(tel_values)
        if _ADDRESS_FIELD.search(field_names):
            specialized_address_values.append(plain_value)
    for attrs in re.findall(r"(?is)<[^>]+>", text):
        field_names = " ".join(re.findall(r"(?i)(?:class|id|name|itemprop|aria-label|data-field)\s*=\s*[\"']([^\"']+)", attrs))
        values = re.findall(r"(?i)(?:value|content|href)\s*=\s*[\"']([^\"']+)", attrs)
        if _PHONE_FIELD.search(field_names):
            specialized_phone_values.extend(values)
        if _ADDRESS_FIELD.search(field_names):
            specialized_address_values.extend(values)
    visible = re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", text)
    visible = re.sub(r"(?s)<[^>]+>", " ", visible)
    visible = html.unescape(visible)
    emails = _unique(_EMAIL.findall(text))
    phone_candidates = _PHONE_RU.findall(visible) + _PHONE_US.findall(visible) + specialized_phone_values
    phones = _unique(re.sub(r"\s+", " ", item).strip(" .,-") for item in phone_candidates if _PHONE_RU.search(item) or _PHONE_US.search(item))
    wallets = _unique(_BTC.findall(text) + _EVM.findall(text) + _TRON.findall(text) + _SOLANA.findall(text))
    addresses = []
    address_candidates = specialized_address_values + re.split(r"[\n\r]+", visible)
    for line in address_candidates:
        line = re.sub(r"\s+", " ", line).strip(" \t,;|")
        has_number = bool(re.search(r"\d", line))
        if line and _ADDRESS_HINT.search(line) and has_number and 10 <= len(line) <= 180 and not (_PHONE_RU.search(line) or _PHONE_US.search(line)):
            addresses.append(line)
    return {"emails": emails, "phones": phones, "wallets": wallets, "addresses": _unique(addresses)}


def _is_api(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return bool(_API_HINT.search(parsed.path) or _API_HINT.search(parsed.query) or parsed.path.lower().endswith((".json", ".xml")))


def _extract_links(text: str, page_url: str, root: str) -> dict[str, list[str]]:
    links: set[str] = set()
    scripts: set[str] = set()
    api_urls: set[str] = set()
    for value in _ATTR.findall(text):
        normalized = _normalize_url(value, page_url, root)
        if not normalized:
            continue
        links.add(normalized)
        parsed = urllib.parse.urlparse(normalized)
        if parsed.path.lower().endswith(".js"):
            scripts.add(normalized)
        if _is_api(normalized):
            api_urls.add(normalized)
    for attrs, inline in _SCRIPT.findall(text):
        src = re.search(r"(?is)\bsrc\s*=\s*[\"']([^\"']+)", attrs)
        if src:
            normalized = _normalize_url(src.group(1), page_url, root)
            if normalized:
                scripts.add(normalized)
                links.add(normalized)
        for raw in re.findall(r"(?i)(?:fetch|axios\.(?:get|post|put|delete)|XMLHttpRequest|\.open)\s*\(\s*[\"']([^\"']+)", inline):
            normalized = _normalize_url(raw, page_url, root)
            if normalized:
                api_urls.add(normalized)
                links.add(normalized)
    domains = sorted({parsed.hostname.lower() for value in links if (parsed := urllib.parse.urlparse(value)).hostname})
    return {"links": sorted(links), "domains": domains, "scripts": sorted(scripts), "api_urls": sorted(api_urls)}


async def async_analyze(target: str, timeout: float = 8.0, max_pages: int = _MAX_PAGES, max_depth: int = _MAX_DEPTH, concurrency: int = 8, progress_callback: Any = None) -> dict[str, Any]:
    host, root_url = normalize_target(target)
    user_agents = list_value(_USER_AGENTS, (_USER_AGENT,))
    proxies = list_value(_PROXIES)
    user_agent_cycle = cycle(user_agents)
    proxy_cycle = cycle(proxies) if proxies else None
    port_scan_task = asyncio.create_task(port_scan.analyze_async(host, timeout))
    root = _base_domain(host)
    start = root_url if urllib.parse.urlparse(root_url).scheme in {"http", "https"} else host_url(host)
    queue: list[tuple[str, int, str]] = [(start, 0, "seed")]
    visited: set[str] = set()
    pages: list[dict[str, Any]] = []
    found = {"emails": [], "phones": [], "wallets": [], "addresses": []}
    technologies: set[str] = set()
    discovered = {"links": [], "domains": [], "scripts": [], "api_urls": []}
    errors: list[dict[str, str]] = []
    sitemap_urls: list[str] = []
    sitemap_error: str | None = None
    try:
        from . import sitemap
        sitemap_result = sitemap.analyze(host, timeout)
        sitemap_urls = [url for url in sitemap_result.get("urls", []) if _normalize_url(url, start, root)]
    except (OSError, ValueError, TypeError) as exc:
        sitemap_error = str(exc)
    queue[0:0] = [(sitemap_url, 0, "sitemap") for sitemap_url in sitemap_urls]
    limit = max(1, min(max_pages, _MAX_PAGES))
    pending: set[asyncio.Task] = set()
    scheduled: set[str] = set()
    workers = max(1, min(int(concurrency), 64))

    async def fetch_page(item: tuple[str, int, str]) -> tuple[tuple[str, int, str], tuple[int, str, str] | Exception]:
        url, _, _ = item
        try:
            user_agent = next(user_agent_cycle)
            proxy = next(proxy_cycle) if proxy_cycle is not None else None
            fetch = partial(_fetch, url, timeout, user_agent, proxy)
            status, content_type, text = await asyncio.to_thread(fetch)
            return item, (status, content_type, text)
        except Exception as exc:
            return item, exc

    while (queue or pending) and len(visited) < limit:
        while queue and len(pending) < workers and len(visited) + len(pending) < limit:
            item = queue.pop(0)
            url, depth, source = item
            if url in scheduled or url in visited or depth > max_depth or not _safe_url(url, root):
                continue
            scheduled.add(url)
            pending.add(asyncio.create_task(fetch_page(item)))
        if not pending:
            continue
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            (url, depth, source), result = task.result()
            visited.add(url)
            if isinstance(result, Exception):
                errors.append({"url": url, "error": str(result)})
                continue
            status, content_type, body = result
            page = {"url": url, "depth": depth, "discovered_by": source, "status_code": status, "content_type": content_type}
            if "html" not in content_type.lower() and not body.lstrip().lower().startswith(("<!doctype html", "<html")):
                page["skipped"] = "non_html"
                pages.append(page)
                continue
            extracted = _extract(body)
            page["contacts"] = extracted
            content_result = content.analyze({
                "status": "ok",
                "url": url,
                "headers": {"content-type": content_type},
                "_body": body,
            })
            page["technologies"] = content_result.get("technologies", [])
            technologies.update(page["technologies"])
            pages.append(page)
            for key in found:
                found[key].extend(extracted[key])
            extracted_links = _extract_links(body, url, root)
            page["links"] = extracted_links["links"]
            page["scripts"] = extracted_links["scripts"]
            page["api_urls"] = extracted_links["api_urls"]
            for key in discovered:
                discovered[key].extend(extracted_links[key])
            if depth < max_depth:
                for link in extracted_links["links"]:
                    normalized = _normalize_url(link, url, root)
                    if normalized and normalized not in scheduled and normalized not in visited:
                        queue.append((normalized, depth + 1, "page"))
            if progress_callback:
                progress_callback({"completed": len(visited), "queued": len(queue) + len(pending), "pages": max_pages})
    summary = {
        "pages_visited": len(visited),
        "pages_with_contacts": sum(1 for page in pages if page.get("contacts")),
        "subdomains_seen": sorted({urllib.parse.urlparse(page["url"]).hostname for page in pages if urllib.parse.urlparse(page["url"]).hostname}),
        "sitemap_urls_seeded": len(sitemap_urls),
        "limits": {"max_pages": max_pages, "max_depth": max_depth},
    }
    all_pages = pages
    internal_host = root
    external_domains = sorted({
        parsed.hostname.lower()
        for value in discovered["links"]
        if (parsed := urllib.parse.urlparse(value)).hostname and not _allowed_host(parsed.hostname, internal_host)
    })
    external_api_urls = sorted({
        value for value in discovered["api_urls"]
        if (parsed := urllib.parse.urlparse(value)).hostname and not _allowed_host(parsed.hostname, internal_host)
    })
    external_script_urls = sorted({
        value for value in discovered["scripts"]
        if (parsed := urllib.parse.urlparse(value)).hostname and not _allowed_host(parsed.hostname, internal_host)
    })
    contact_sources = []
    for page in all_pages:
        contacts = page.get("contacts", {})
        if any(contacts.get(key) for key in found):
            contact_sources.append({
                "url": page["url"],
                "depth": page["depth"],
                "emails": contacts.get("emails", []),
                "phones": contacts.get("phones", []),
                "wallets": contacts.get("wallets", []),
                "addresses": contacts.get("addresses", []),
            })
    summary = {
        **summary,
        "internal_links_found": len({value for value in discovered["links"] if (parsed := urllib.parse.urlparse(value)).hostname and _allowed_host(parsed.hostname, internal_host)}),
        "external_domains": len(external_domains),
        "external_api_urls": len(external_api_urls),
        "external_scripts": len(external_script_urls),
    }
    report = {
        "tool": "resource-parser",
        "target": target.strip(),
        "root_domain": root,
        "summary": summary,
        "contacts": {key: _unique(values) for key, values in found.items()},
        "technologies": sorted(technologies),
        "contact_sources": contact_sources,
        "external_resources": {
            "domains": external_domains,
            "api_urls": external_api_urls,
            "scripts": external_script_urls,
        },
    }
    try:
        report["port_scan"] = await port_scan_task
    except Exception as exc:
        report["port_scan"] = port_scan.unavailable(host, "completed_with_errors", str(exc))
    try:
        dns_result = dns.analyze(host)
        report["domain"] = {
            "dns": dns_result,
            "ip": dns.analyze_ip(dns_result),
            "rdap": rdap.analyze(host, timeout),
            "whois": whois.analyze(host, timeout),
            "tls": tls.analyze(host, timeout),
            "redirects": redirects.analyze(host, timeout),
            "subdomains": subdomains.analyze(host, timeout=min(timeout, 3)),
        }
        report["domain"]["history"] = record_history(host, dns_result, report["domain"]["tls"])
    except Exception as exc:
        report["domain"] = {"status": "partial", "error": str(exc)}
    return report


def analyze(target: str, timeout: float = 8.0, max_pages: int = _MAX_PAGES, max_depth: int = _MAX_DEPTH, concurrency: int = 8, progress_callback: Any = None) -> dict[str, Any]:
    """Synchronous compatibility wrapper around the asynchronous crawler."""
    return asyncio.run(async_analyze(target, timeout, max_pages, max_depth, concurrency, progress_callback))