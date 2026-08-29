"""Passive username enumeration against configured public profile URLs."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import re
from typing import Callable
from urllib.parse import quote, urlparse
import random

import requests

DEFAULT_WORDLIST = Path(__file__).resolve().parents[2] / "wordlists" / "username_sites.txt"
DEFAULT_RULES = Path(__file__).resolve().parents[2] / "wordlists" / "username_rules.json"
DEFAULT_REMOTE_CACHE = Path(__file__).resolve().parents[2] / "wordlists" / "username_remote_rules.json"
REMOTE_RULES_URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
WAF_MARKERS = ("captcha", "cloudflare", "access denied", "verify you are human", "challenge-error-text", "perimeterxidentifiers")
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
)


def normalize_username(username: str) -> str:
    value = username.strip()
    if value.startswith("@"):
        value = value[1:]
    if not value or len(value) > 64 or not USERNAME_RE.fullmatch(value):
        raise ValueError("username must contain only letters, digits, '.', '_' or '-' and be 1–64 characters long")
    return value


def load_templates(path: str | Path = DEFAULT_WORDLIST) -> list[str]:
    wordlist = Path(path)
    if not wordlist.is_file():
        raise OSError(f"username wordlist not found: {wordlist}")
    result, seen = [], set()
    for raw in wordlist.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        parsed = urlparse(line)
        if not line or line.startswith("#") or "{username}" not in line or parsed.scheme != "https" or not parsed.netloc or line in seen:
            continue
        seen.add(line)
        result.append(line)
    if not result:
        raise ValueError(f"username wordlist is empty: {wordlist}")
    return result


def load_rules(path: str | Path = DEFAULT_RULES) -> list[dict]:
    rules_path = Path(path)
    if not rules_path.is_file():
        return []
    data = json.loads(rules_path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else []


def _convert_remote_rule(name: str, raw: dict) -> dict | None:
    template = raw.get("url")
    if not isinstance(template, str) or "{}" not in template:
        return None
    error_type = raw.get("errorType")
    if error_type not in {"status_code", "message", "response_url"}:
        return None
    rule = {
        "name": name,
        "url": template.replace("{}", "{username}"),
        "source": "remote_sherlock",
        "found_statuses": [200],
        "not_found_statuses": [404],
        "headers": raw.get("headers", {}),
    }
    if raw.get("regexCheck"):
        rule["regex"] = raw["regexCheck"]
    if raw.get("request_method") in {"GET", "HEAD"}:
        rule["method"] = raw["request_method"]
    if error_type == "status_code" and raw.get("errorCode") is not None:
        codes = raw["errorCode"] if isinstance(raw["errorCode"], list) else [raw["errorCode"]]
        rule["not_found_statuses"] = codes
    if error_type == "message" and raw.get("errorMsg"):
        rule["negative_strings"] = raw["errorMsg"] if isinstance(raw["errorMsg"], list) else [raw["errorMsg"]]
    if error_type == "response_url":
        rule["allow_redirects"] = True
    return rule


def load_remote_rules(cache_path: str | Path = DEFAULT_REMOTE_CACHE, timeout: float = 15.0, offline: bool = False, update: bool = False) -> tuple[list[dict], str]:
    cache = Path(cache_path)
    if not offline and (update or not cache.is_file()):
        response = requests.get(REMOTE_RULES_URL, timeout=timeout, headers={"User-Agent": USER_AGENTS[0], "Accept": "application/json"})
        response.raise_for_status()
        raw = response.json()
        converted = [_convert_remote_rule(name, item) for name, item in raw.items() if name != "$schema" and isinstance(item, dict)]
        rules = [item for item in converted if item]
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(rules, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return rules, "remote_sherlock"
    return load_rules(cache), "remote_cache"


def _check(rule: dict, username: str, timeout: float, session: requests.Session) -> dict:
    template = rule["url"]
    url = template.replace("{username}", quote(username, safe=""))
    result = {"site": rule.get("name") or urlparse(template).netloc, "url": url, "source": rule.get("source", "built_in")}
    if rule.get("regex") and re.fullmatch(rule["regex"], username) is None:
        result.update(status="illegal", reason="username does not match site rules")
        return result
    method = str(rule.get("method", "GET")).upper()
    if method not in {"GET", "HEAD"}:
        result.update(status="error", reason="unsupported safe method")
        return result
    headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.8"}
    headers.update(rule.get("headers", {}))
    try:
        response = session.request(method, url, timeout=timeout, allow_redirects=rule.get("allow_redirects", True), headers=headers)
        result.update(http_status=response.status_code, final_url=response.url, redirected=response.url != url)
        body = (response.text or "")[:500_000].lower() if method != "HEAD" else ""
        if any(marker in body for marker in WAF_MARKERS):
            result.update(status="waf", reason="anti-bot challenge detected")
        elif response.status_code == 429:
            result["status"] = "rate_limited"
        elif response.status_code in (401, 403) or any(marker in body for marker in WAF_MARKERS):
            result["status"] = "blocked"
        elif response.status_code in set(rule.get("not_found_statuses", [404])):
            result["status"] = "not_found"
        elif response.status_code in set(rule.get("found_statuses", [200])):
            result["status"] = "not_found" if any(str(item).lower() in body for item in rule.get("negative_strings", [])) else "found"
        else:
            result["status"] = "error"
    except requests.exceptions.Timeout:
        result.update(status="timeout", http_status=None)
    except requests.exceptions.RequestException as exc:
        result.update(status="error", http_status=None, error=str(exc))
    return result


def analyze(username: str, timeout: float = 8.0, wordlist: str | Path = DEFAULT_WORDLIST, rules: str | Path = DEFAULT_RULES, remote_cache: str | Path = DEFAULT_REMOTE_CACHE, workers: int = 12, progress_callback: Callable[[dict], None] | None = None, offline: bool = False, update_sites: bool = False) -> dict:
    normalized = normalize_username(username)
    try:
        entries, remote_source = load_remote_rules(remote_cache, timeout=timeout, offline=offline, update=update_sites)
    except (requests.RequestException, ValueError, OSError) as exc:
        if offline:
            raise
        entries, remote_source = load_rules(remote_cache), "remote_cache_fallback"
        remote_error = str(exc)
    else:
        remote_error = None
    entries = [dict(item, source=remote_source) for item in entries]
    entries.extend(dict(item, source="local_rules") for item in load_rules(rules))

    # Keep one check per URL template. The local wordlist may intentionally
    # contain URLs already supplied by remote or local rules, and comparing
    # only the source would otherwise create duplicate report rows.
    unique_entries = []
    known_urls = set()
    for entry in entries:
        template = entry.get("url")
        if not isinstance(template, str) or template in known_urls:
            continue
        known_urls.add(template)
        unique_entries.append(entry)
    for template in load_templates(wordlist):
        if template not in known_urls:
            known_urls.add(template)
            unique_entries.append({"url": template, "source": "user_wordlist"})
    entries = unique_entries
    if not entries:
        raise ValueError("username site configuration is empty")
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(int(workers), len(entries)))) as executor:
        futures = [executor.submit(_check, item, normalized, timeout, requests.Session()) for item in entries]
        for index, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            if progress_callback:
                progress_callback({"completed": index, "total": len(entries), "result": result})
    results.sort(key=lambda item: item["site"].lower())
    statuses = ("found", "not_found", "blocked", "waf", "rate_limited", "timeout", "illegal", "error")
    summary = {"checked": len(results), **{status: sum(item["status"] == status for item in results) for status in statuses}}
    report = {"tool": "username-search", "target": normalized, "query": {"username": normalized}, "sources": {"remote": remote_source, "local_rules": str(rules), "user_wordlist": str(wordlist)}, "summary": summary, "results": results}
    if remote_error:
        report["sources"]["remote_error"] = remote_error
    return report