"""Basic subdomain discovery using CT logs and DNS wordlist probing."""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import urllib.error
import urllib.request

from .common import normalize_target
from .dns import analyze as dns_analyze


_MAX_WORKERS = 16


def _ct(host: str, timeout: float) -> list[str]:
    try:
        with urllib.request.urlopen(f"https://crt.sh/?q=%25.{host}&output=json", timeout=timeout) as response:
            entries = json.loads(response.read(2_000_000))
        return sorted({name.strip().lower().lstrip("*.") for item in entries for name in item.get("name_value", "").splitlines() if name.strip().lower().endswith(host)})
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return []


def _probe(candidate: str) -> str | None:
    return candidate if dns_analyze(candidate).get("status") == "ok" else None


def _brute_force(candidates: list[str]) -> set[str]:
    if not candidates:
        return set()
    workers = min(_MAX_WORKERS, len(candidates))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return {candidate for candidate in executor.map(_probe, candidates) if candidate is not None}


def analyze(target: str, timeout: float = 3.0, wordlist: str | None = None) -> dict:
    host, _ = normalize_target(target)
    found = {"certificate_transparency": set(_ct(host, timeout)), "dns": set(), "passive_dns": set(), "brute_force": set()}
    wordlist_path = Path(wordlist) if wordlist else Path(__file__).resolve().parents[2] / "wordlists" / "subdomains.txt"
    try:
        with wordlist_path.open(encoding="utf-8") as stream:
            candidates = [f"{line.strip()}.{host}" for line in stream if line.strip() and not line.startswith("#")]
        found["brute_force"].update(_brute_force(candidates))
    except (OSError, UnicodeError):
        pass
    names = sorted(set().union(*found.values()))
    return {"status": "ok", "domain": host, "sources": {key: sorted(value) for key, value in found.items()}, "subdomains": names, "count": len(names)}