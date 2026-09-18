"""Shared helpers for analyzers."""

import ipaddress
from urllib.parse import urlparse


def normalize_target(value: str) -> tuple[str, str]:
    value = value.strip()
    # An unbracketed IPv6 literal contains colons but is not a URL. Bracket it
    # before parsing so urllib does not mistake the first hextet for a port.
    candidate = value
    if "://" not in candidate:
        try:
            ipaddress.IPv6Address(candidate)
            candidate = f"[{candidate}]"
        except ValueError:
            pass
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    if not parsed.hostname:
        raise ValueError("target must be a valid domain or URL")
    host = parsed.hostname.rstrip(".").lower()
    if any(c.isspace() for c in host):
        raise ValueError("target must contain a valid domain name or IP address")
    try:
        address = ipaddress.ip_address(host)
        url_host = f"[{host}]" if address.version == 6 else host
        return host, f"{parsed.scheme}://{url_host}{parsed.path or '/'}"
    except ValueError:
        if "." not in host:
            raise ValueError("target must contain a valid domain name or IP address")
    return host, f"{parsed.scheme}://{host}{parsed.path or '/'}"


def unavailable(error: Exception | str) -> dict:
    return {"status": "unavailable", "error": str(error)}


def url_host(host: str) -> str:
    """Return a host formatted for use in an HTTP URL."""
    try:
        return f"[{ipaddress.IPv6Address(host)}]"
    except ValueError:
        return host


def host_url(host: str, path: str = "/", scheme: str = "https") -> str:
    """Build a valid URL for either a DNS name, IPv4, or IPv6 literal."""
    return f"{scheme}://{url_host(host)}{path if path.startswith('/') else '/' + path}"
