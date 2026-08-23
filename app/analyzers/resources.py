"""Small resource endpoints useful for user-safety analysis."""

import ssl
import urllib.error
import urllib.request


def _fetch(url: str, timeout: float) -> dict:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "phishintel/1.0"})
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            return {"status": "ok", "url": response.geturl(), "status_code": response.status, "body": response.read(256_000).decode("utf-8", errors="replace")}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"status": "unavailable", "error": str(exc)}


def analyze(host: str, timeout: float = 8.0) -> dict:
    result = {}
    for name in ("robots.txt", ".well-known/security.txt"):
        result[name] = _fetch(f"https://{host}/{name}", timeout)
    return result