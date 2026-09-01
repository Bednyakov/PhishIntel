"""Configurable, privacy-conscious reputation checks."""

import base64
import json
import os
from ..config import bool_value, env
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def _request(url: str, timeout: float, headers: dict[str, str] | None = None) -> tuple[int, dict, bytes]:
    request = urllib.request.Request(url, headers={"User-Agent": "phishintel/1.0", **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
        return response.status, dict(response.headers.items()), response.read(512_000)


def _json_request(url: str, timeout: float, headers: dict[str, str] | None = None) -> tuple[int, dict]:
    status, _, body = _request(url, timeout, {"Accept": "application/json", **(headers or {})})
    return status, json.loads(body.decode("utf-8", errors="replace"))


def _clean_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _entities(target: str, http_result: dict, redirects: dict, content: dict, ip_result: dict) -> list[dict[str, str]]:
    values: list[dict[str, str]] = [{"type": "domain", "value": target}]
    urls = []
    if http_result.get("url"):
        urls.append(http_result["url"])
    if redirects.get("final_url"):
        urls.append(redirects["final_url"])
    urls.extend(item.get("to", "") for item in redirects.get("chain", []) if item.get("to"))
    urls.extend(form.get("action") for form in content.get("forms", []) if form.get("action"))
    urls.extend(content.get("scripts", []))
    urls.extend(content.get("external_domains", []))
    seen = {target}
    for value in urls:
        value = _clean_url(value) if "://" in value else value
        if value and value not in seen:
            seen.add(value)
            values.append({"type": "url" if "://" in value else "domain", "value": value})
    for address in ip_result.get("addresses", []) or ([ip_result.get("address")] if ip_result.get("address") else []):
        if address and address not in seen:
            seen.add(address)
            values.append({"type": "ip", "value": address})
    return values


def _google_safe_browsing(value: str, timeout: float) -> dict:
    key = env("PHISHINTEL_GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return {"name": "google_safe_browsing", "status": "not_configured"}
    payload = {"client": {"clientId": "phishintel", "clientVersion": "1.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": value}]}}
    try:
        request = urllib.request.Request(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={urllib.parse.quote(key)}", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "User-Agent": "phishintel/1.0"}, method="POST")
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            data = json.loads(response.read(100_000).decode("utf-8", errors="replace"))
        matches = data.get("matches", [])
        return {"name": "google_safe_browsing", "status": "malicious" if matches else "clean", "matches": [{"threat_type": item.get("threatType"), "platform": item.get("platformType")} for item in matches]}
    except (OSError, urllib.error.URLError, ValueError) as exc:
        return {"name": "google_safe_browsing", "status": "unavailable", "error": str(exc)}


def _virustotal(value: str, entity_type: str, timeout: float) -> dict:
    key = env("PHISHINTEL_VIRUSTOTAL_KEY")
    if not key:
        return {"name": "virustotal", "status": "not_configured"}
    if entity_type == "ip":
        path = f"ip_addresses/{value}"
    elif entity_type == "domain":
        path = f"domains/{value}"
    else:
        encoded = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        path = f"urls/{encoded}"
    try:
        _, data = _json_request(f"https://www.virustotal.com/api/v3/{path}", timeout, {"x-apikey": key})
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"name": "virustotal", "status": "malicious" if stats.get("malicious", 0) else ("suspicious" if stats.get("suspicious", 0) else "clean"), "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "undetected": stats.get("undetected", 0), "harmless": stats.get("harmless", 0)}
    except urllib.error.HTTPError as exc:
        return {"name": "virustotal", "status": "not_found" if exc.code == 404 else "unavailable", "error": str(exc)}
    except (OSError, ValueError) as exc:
        return {"name": "virustotal", "status": "unavailable", "error": str(exc)}


def _urlhaus(value: str, timeout: float) -> dict:
    if not value.startswith(("http://", "https://")):
        return {"name": "urlhaus", "status": "not_applicable"}
    try:
        request = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/url/", data=urllib.parse.urlencode({"url": value}).encode(), headers={"User-Agent": "phishintel/1.0"}, method="POST")
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            data = json.loads(response.read(100_000).decode("utf-8", errors="replace"))
        return {"name": "urlhaus", "status": "malicious" if data.get("query_status") == "ok" else "not_found", "threat": data.get("threat"), "url_status": data.get("url_status")}
    except (OSError, urllib.error.URLError, ValueError) as exc:
        return {"name": "urlhaus", "status": "unavailable", "error": str(exc)}


def analyze(target: str, http_result: dict, redirects: dict, content: dict, ip_result: dict, timeout: float = 8.0) -> dict:
    checked_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    entities = []
    for entity in _entities(target, http_result, redirects, content, ip_result):
        value, entity_type = entity["value"], entity["type"]
        providers = []
        if env("PHISHINTEL_VIRUSTOTAL_KEY"):
            providers.append(_virustotal(value, entity_type, timeout))
        if entity_type in {"url", "domain"}:
            if env("PHISHINTEL_GOOGLE_SAFE_BROWSING_KEY"):
                providers.append(_google_safe_browsing(value if entity_type == "url" else f"https://{value}/", timeout))
            if entity_type == "url" and bool_value("PHISHINTEL_URLHAUS_ENABLED"):
                providers.append(_urlhaus(value, timeout))
        if providers:
            entities.append({**entity, "providers": providers})
    statuses = [provider["status"] for entity in entities for provider in entity["providers"]]
    if any(status == "malicious" for status in statuses):
        status = "malicious"
    elif any(status == "suspicious" for status in statuses):
        status = "suspicious"
    elif statuses:
        status = "ok"
    else:
        return {"status": "not_configured"}
    return {"status": status, "checked_at": checked_at, "entities": entities, "summary": {"malicious_sources": statuses.count("malicious"), "suspicious_sources": statuses.count("suspicious"), "clean_sources": statuses.count("clean"), "unavailable_sources": statuses.count("unavailable")}}