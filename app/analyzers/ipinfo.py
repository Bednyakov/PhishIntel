"""IP metadata lookup through ipinfo.io."""

import json
import ssl
import urllib.error
import urllib.request


_MAX_BYTES = 100_000
_FIELDS = ("ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone")


def analyze(address: str | None, timeout: float = 8.0) -> dict | None:
    """Return validated ipinfo data, or ``None`` when it is unavailable/invalid."""
    if not address:
        return None

    request = urllib.request.Request(
        f"https://ipinfo.io/{address}/json",
        headers={"User-Agent": "phishintel/1.0", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            if response.status < 200 or response.status >= 300:
                return None
            payload = json.loads(response.read(_MAX_BYTES + 1).decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict) or not isinstance(payload.get("ip"), str) or not payload["ip"].strip():
        return None
    return {key: payload[key] for key in _FIELDS if key in payload}