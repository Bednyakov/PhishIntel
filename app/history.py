"""Small dependency-free JSONL history store for DNS and TLS observations."""

import datetime as dt
import json
import os
from .config import env
from pathlib import Path
from typing import Any

_DEFAULT_FILE = Path("data/history.jsonl")
_MAX_RECORDS = 50


def _path() -> Path:
    return Path(env("PHISHINTEL_HISTORY_FILE", str(_DEFAULT_FILE)))


def _snapshot(dns_result: dict, tls_result: dict) -> dict[str, Any]:
    dns = {key: dns_result.get(key) for key in ("status", "a", "aaaa", "cname", "mx", "ns", "txt", "caa", "soa")}
    tls = {key: tls_result.get(key) for key in ("status", "version", "cipher", "subject", "issuer", "not_before", "not_after")}
    return {"dns": dns, "tls": tls}


def _read(path: Path, host: str) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    records = []
    for line in lines:
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if record.get("target") == host and isinstance(record.get("snapshot"), dict):
            records.append(record)
    return records[-_MAX_RECORDS:]


def record(host: str, dns_result: dict, tls_result: dict) -> dict:
    path = _path()
    previous = _read(path, host)
    snapshot = _snapshot(dns_result, tls_result)
    entry = {"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(), "target": host, "snapshot": snapshot}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError as exc:
        return {"status": "unavailable", "error": str(exc), "count": len(previous), "records": previous, "changes": []}
    changes = []
    if previous:
        old = previous[-1]["snapshot"]
        for section in ("dns", "tls"):
            for key, value in snapshot[section].items():
                if old.get(section, {}).get(key) != value:
                    changes.append({"section": section, "field": key, "before": old.get(section, {}).get(key), "after": value})
    return {"status": "ok", "count": len(previous) + 1, "records": previous + [entry], "changes": changes}