"""Shared helpers for analyzers."""

from urllib.parse import urlparse


def normalize_target(value: str) -> tuple[str, str]:
    value = value.strip()
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if not parsed.hostname:
        raise ValueError("target must be a valid domain or URL")
    host = parsed.hostname.rstrip(".").lower()
    if any(c.isspace() for c in host) or "." not in host:
        raise ValueError("target must contain a valid domain name")
    return host, f"{parsed.scheme}://{host}{parsed.path or '/'}"


def unavailable(error: Exception | str) -> dict:
    return {"status": "unavailable", "error": str(error)}
