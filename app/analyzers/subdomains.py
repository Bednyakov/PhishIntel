"""Basic subdomain discovery using CT logs and DNS wordlist probing."""

import json
from pathlib import Path
import urllib.error
import urllib.request

from .common import normalize_target
from .dns import analyze as dns_analyze


def _ct(host: str, timeout: float) -> list[str]:
    try:
        with urllib.request.urlopen(f"https://crt.sh/?q=%25.{host}&output=json", timeout=timeout) as response:
            entries = json.loads(response.read(2_000_000))
        return sorted({name.strip().lower().lstrip("*.") for item in entries for name in item.get("name_value", "").splitlines() if name.strip().lower().endswith(host)})
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return []


def analyze(target: str, timeout: float = 3.0, wordlist: str | None = None) -> dict:
    host, _ = normalize_target(target)
    found = {"certificate_transparency": set(_ct(host, timeout)), "dns": set(), "passive_dns": set(), "brute_force": set()}
    wordlist_path = Path(wordlist) if wordlist else Path(__file__).resolve().parents[2] / "wordlists" / "subdomains.txt"
    try:
        with wordlist_path.open(encoding="utf-8") as stream:
            candidates = [f"{line.strip()}.{host}" for line in stream if line.strip() and not line.startswith("#")]
        for candidate in candidates:
            if dns_analyze(candidate).get("status") == "ok":
                found["brute_force"].add(candidate)
    except (OSError, UnicodeError):
        pass
    names = sorted(set().union(*found.values()))
    return {"status": "ok", "domain": host, "sources": {key: sorted(value) for key, value in found.items()}, "subdomains": names, "count": len(names)}