"""Passive email-account checks against locally configured site rules."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import re
from typing import Any, Callable
from urllib.parse import quote, urlparse

import requests

from .email import normalize_email

DEFAULT_RULES = Path(__file__).resolve().parents[2] / "wordlists" / "email_search_rules.json"
DEFAULT_REMOTE_CACHE = Path(__file__).resolve().parents[2] / "wordlists" / "email_search_remote_rules.json"
REMOTE_RULES_URL = "https://raw.githubusercontent.com/KatrielMoses/MailAccess/main/data/mailaccess-extra-sites.json"
WAF_MARKERS = ("captcha", "cloudflare", "access denied", "verify you are human", "challenge")


def _normalize_rule(name: str, raw: dict[str, Any], source: str) -> dict[str, Any] | None:
    endpoint = raw.get("uri_check") or raw.get("url")
    if not isinstance(endpoint, str):
        return None
    method = str(raw.get("method", raw.get("requestMethod", "GET"))).upper()
    if method not in {"GET", "POST"}:
        return None
    payload = raw.get("payload", raw.get("requestPayload"))
    encoded = json.dumps(payload, ensure_ascii=False) if payload is not None else ""
    has_placeholder = any(token in f"{endpoint} {encoded} {json.dumps(raw.get('headers', {}), ensure_ascii=False)}" for token in ("{email}", "{username}"))
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc or not has_placeholder:
        return None
    return {
        "name": raw.get("name") or name,
        "url": endpoint,
        "method": method,
        "payload": payload,
        "headers": raw.get("headers", {}),
        "found_statuses": raw.get("found_statuses", raw.get("positive_statuses", [raw.get("e_code", 200)])),
        "not_found_statuses": raw.get("not_found_statuses", raw.get("negative_statuses", [raw.get("m_code", 404)])),
        "found_strings": raw.get("found_strings", raw.get("positive_strings", raw.get("e_string"))),
        "not_found_strings": raw.get("not_found_strings", raw.get("negative_strings", raw.get("m_string"))),
        "disabled": bool(raw.get("disabled", False)),
        "disabled_reason": raw.get("disabled_reason"),
        "pre_check": raw.get("pre_check"),
        "category": raw.get("cat") or raw.get("category"),
        "source": source,
    }


def _parse_catalog(payload: Any, source: str) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        return [rule for name, raw in payload.items() if isinstance(raw, dict) and (rule := _normalize_rule(name, raw, source))]
    if isinstance(payload, list):
        return [rule for index, raw in enumerate(payload) if isinstance(raw, dict) and (rule := _normalize_rule(str(index), raw, source))]
    raise ValueError("email search catalog must be a JSON object or list")


def load_rules(path: str | Path = DEFAULT_RULES, include_disabled: bool = False) -> list[dict[str, Any]]:
    rules_path = Path(path)
    if not rules_path.is_file():
        raise OSError(f"email search rules not found: {rules_path}")
    payload = json.loads(rules_path.read_text(encoding="utf-8"))
    result = _parse_catalog(payload, "local_rules")
    if not include_disabled:
        result = [rule for rule in result if not rule.get("disabled")]
    if not result and payload:
        raise ValueError(f"email search rules are empty: {rules_path}")
    return result


def load_remote_rules(cache_path: str | Path = DEFAULT_REMOTE_CACHE, timeout: float = 15.0, offline: bool = False, update: bool = False, include_disabled: bool = True) -> tuple[list[dict[str, Any]], str]:
    """Download and cache the original MailAccess catalog, like username rules."""
    cache = Path(cache_path)
    if not offline and (update or not cache.is_file()):
        response = requests.get(REMOTE_RULES_URL, timeout=timeout, headers={"User-Agent": "PhishIntel/1.0", "Accept": "application/json"})
        response.raise_for_status()
        rules = _parse_catalog(response.json(), "mailaccess_remote")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(rules, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return ([rule for rule in rules if include_disabled or not rule.get("disabled")], "mailaccess_remote")
    return load_rules(cache, include_disabled=include_disabled), "mailaccess_cache"


def _format(value: Any, email: str) -> Any:
    if isinstance(value, str):
        return value.replace("{email}", quote(email, safe="")).replace("{username}", quote(email, safe=""))
    if isinstance(value, dict):
        return {key: _format(item, email) for key, item in value.items()}
    if isinstance(value, list):
        return [_format(item, email) for item in value]
    return value


def _contains(body: str, expected: Any) -> bool:
    if expected is None:
        return False
    values = expected if isinstance(expected, list) else [expected]
    return any(str(value).lower() in body for value in values if value is not None and str(value))


def _check(rule: dict[str, Any], address: str, timeout: float, session_factory: Callable[[], requests.Session]) -> dict[str, Any]:
    template = rule["url"]
    url = _format(template, address)
    name = str(rule.get("name") or urlparse(template).netloc)
    result: dict[str, Any] = {"site": name, "url": url, "source": rule.get("source", "local_rules")}
    if rule.get("pre_check"):
        result["pre_check_required"] = True
    if rule.get("disabled"):
        result.update(status="disabled", reason=rule.get("disabled_reason") or "disabled in source catalog")
        return result
    headers = _format(rule.get("headers", {}), address)
    payload = _format(rule.get("payload", rule.get("requestPayload")), address)
    try:
        session = session_factory()
        method = rule["method"]
        if method == "POST":
            response = session.post(url, json=payload, headers=headers, timeout=timeout, allow_redirects=bool(rule.get("allow_redirects", False)))
        else:
            response = session.get(url, headers=headers, timeout=timeout, allow_redirects=bool(rule.get("allow_redirects", False)))
        body = response.text.lower()
        if response.status_code in (401, 403, 429) or any(marker in body for marker in WAF_MARKERS):
            result.update(status="blocked", http_status=response.status_code)
        else:
            positive_status = rule.get("found_statuses", rule.get("positive_statuses", [rule.get("e_code", 200)]))
            negative_status = rule.get("not_found_statuses", rule.get("negative_statuses", [rule.get("m_code", 404)]))
            positive_text = rule.get("found_strings", rule.get("positive_strings", rule.get("e_string")))
            negative_text = rule.get("not_found_strings", rule.get("negative_strings", rule.get("m_string")))
            is_positive = response.status_code in set(int(item) for item in (positive_status if isinstance(positive_status, list) else [positive_status]))
            is_negative = response.status_code in set(int(item) for item in (negative_status if isinstance(negative_status, list) else [negative_status]))
            if is_positive and (positive_text is None or _contains(body, positive_text)) and not _contains(body, negative_text):
                result.update(status="found", http_status=response.status_code)
            elif is_negative or (positive_text is not None and not _contains(body, positive_text)):
                result.update(status="not_found", http_status=response.status_code)
            else:
                result.update(status="uncertain", http_status=response.status_code)
    except requests.exceptions.Timeout:
        result.update(status="timeout", http_status=None)
    except requests.exceptions.RequestException as exc:
        result.update(status="error", http_status=None, error=str(exc))
    return result


def analyze(email: str, timeout: float = 8.0, rules: str | Path = DEFAULT_RULES, remote_cache: str | Path = DEFAULT_REMOTE_CACHE, workers: int = 12, progress_callback: Callable[[dict[str, Any]], None] | None = None, session_factory: Callable[[], requests.Session] | None = None, offline: bool = False, update_sites: bool = False, include_disabled: bool = False) -> dict[str, Any]:
    normalized = normalize_email(email)
    remote_error = None
    try:
        entries, rules_source = load_remote_rules(remote_cache, timeout=timeout, offline=offline, update=update_sites, include_disabled=True)
    except (requests.RequestException, ValueError, OSError) as exc:
        if offline:
            raise
        entries, rules_source = load_rules(rules, include_disabled=True), "local_fallback"
        remote_error = str(exc)
    entries.extend(load_rules(rules, include_disabled=True))
    unique: dict[str, dict[str, Any]] = {}
    for entry in entries:
        unique.setdefault(entry["url"], entry)
    entries = list(unique.values())
    disabled_entries = [entry for entry in entries if entry.get("disabled")]
    runnable_entries = [entry for entry in entries if include_disabled or not entry.get("disabled")]
    session_factory = session_factory or requests.Session
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(int(workers), len(runnable_entries)))) as executor:
        futures = [executor.submit(_check, rule, normalized, timeout, session_factory) for rule in runnable_entries]
        for index, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            if progress_callback:
                progress_callback({"completed": index, "total": len(entries), "result": result})
    results.extend(_check(rule, normalized, timeout, session_factory) for rule in disabled_entries)
    results.sort(key=lambda item: item["site"].lower())
    statuses = ("found", "not_found", "blocked", "timeout", "uncertain", "error", "disabled")
    summary = {"checked": len(results), **{status: sum(item["status"] == status for item in results) for status in statuses}}
    summary["catalog_rules"] = len(entries)
    summary["disabled"] = sum(item["status"] == "disabled" for item in results)
    report = {"tool": "email-search", "target": normalized, "query": {"email": normalized}, "sources": {"catalog": rules_source, "remote_cache": str(remote_cache), "local_rules": str(rules), "external_apis": []}, "summary": summary, "results": results}
    if remote_error:
        report["sources"]["remote_error"] = remote_error
    return report