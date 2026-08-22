"""RDAP registration analyzer with IANA bootstrap discovery."""

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .common import normalize_target, unavailable

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
FALLBACK_SERVERS = ("https://rdap.org",)


def _event(data: dict, *actions: str) -> str | None:
    wanted = set(actions)
    for event in data.get("events", []):
        if event.get("eventAction") in wanted:
            return event.get("eventDate")
    return None


def _bootstrap_servers(tld: str, timeout: float) -> list[str]:
    request = urllib.request.Request(BOOTSTRAP_URL, headers={"Accept": "application/json", "User-Agent": "phishintel/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read(2_000_000))
    for service in data.get("services", []):
        if tld in [str(value).lower().lstrip(".") for value in service[0]]:
            return [server.rstrip("/") for server in service[1]]
    return []


def _registrar(data: dict) -> str | None:
    for entity in data.get("entities", []):
        if "registrar" not in entity.get("roles", []):
            continue
        values = entity.get("vcardArray", [None, []])[1]
        for item in values:
            if len(item) > 3 and item[0] == "fn":
                return item[3]
    return None


def _registration(data: dict) -> dict:
    created = _event(data, "registration")
    updated = _event(data, "last changed", "last update")
    expires = _event(data, "expiration", "expiry")
    age_days = None
    if created:
        try:
            age_days = max(0, (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days)
        except ValueError:
            pass
    category = "new" if age_days is not None and age_days < 180 else "recent" if age_days is not None and age_days < 730 else "old" if age_days is not None else None
    return {"created": created, "updated": updated, "expires": expires, "registrar": _registrar(data), "status": data.get("status", []), "age": {"days": age_days, "category": category}}


def analyze(target: str, timeout: float = 8.0) -> dict:
    host, _ = normalize_target(target)
    tld = host.rsplit(".", 1)[-1].lower()
    try:
        servers = _bootstrap_servers(tld, timeout)
        source = "iana-bootstrap"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, IndexError) as exc:
        servers = list(FALLBACK_SERVERS)
        source = "fallback"
    if not servers:
        return {"status": "unsupported", "source": source, "tld": tld, "registration": None}
    last_error = None
    for server in servers + [item for item in FALLBACK_SERVERS if item not in servers]:
        request = urllib.request.Request(f"{server}/domain/{host}", headers={"Accept": "application/rdap+json, application/json", "User-Agent": "phishintel/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read(2_000_000))
                status = getattr(response, "status", 200)
            return {"status": "ok", "source": source, "server": server, "http_status": status, "registration": _registration(data)}
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {"status": "not_found", "source": source, "server": server, "http_status": 404, "registration": None}
            last_error = str(exc)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError, IndexError) as exc:
            last_error = str(exc)
    return {"status": "unavailable", "source": source, "server": servers[0], "error": last_error or "RDAP lookup failed", "registration": None}