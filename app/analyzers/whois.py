"""WHOIS registration analyzer using the system client or TCP port 43."""

import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone

from .common import normalize_target

WHOIS_SERVERS = {
    "ru": "whois.tcinet.ru",
    "рф": "whois.tcinet.ru",
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "me": "whois.nic.me",
}
DATE_KEYS = ("creation date", "created", "registered on", "registration time")
UPDATED_KEYS = ("updated date", "last updated", "changed", "last modified")
EXPIRES_KEYS = ("registry expiry date", "expiration date", "expiry date", "expires")


def _server_for(host: str) -> str:
    return WHOIS_SERVERS.get(host.rsplit(".", 1)[-1].lower(), "whois.iana.org")


def _query(host: str, server: str, timeout: float) -> tuple[str, str]:
    if shutil.which("whois"):
        completed = subprocess.run(["whois", "-h", server, host], capture_output=True, text=True, timeout=timeout, check=False)
        return completed.stdout, "command"
    with socket.create_connection((server, 43), timeout=timeout) as connection:
        connection.sendall(f"{host}\r\n".encode("ascii"))
        chunks = []
        while True:
            chunk = connection.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace"), "tcp"


def _find_value(lines: list[str], keys: tuple[str, ...]) -> str | None:
    for line in lines:
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() in keys and value.strip():
            return value.strip()
    return None


def _date(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return value


def analyze(target: str, timeout: float = 8.0) -> dict:
    host, _ = normalize_target(target)
    server = _server_for(host)
    try:
        raw, source = _query(host, server, timeout)
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        return {"status": "unavailable", "server": server, "source": "unknown", "error": str(exc)}
    lines = raw.splitlines()
    lowered = raw.lower()
    if not raw.strip() or any(marker in lowered for marker in ("no match", "not found", "no entries found")):
        return {"status": "not_found", "server": server, "source": source, "domain": host, "raw_lines_count": len(lines)}
    created, updated, expires = _date(_find_value(lines, DATE_KEYS)), _date(_find_value(lines, UPDATED_KEYS)), _date(_find_value(lines, EXPIRES_KEYS))
    statuses = sorted({value.strip() for line in lines if re.search(r"status", line, re.I) for value in [line.split(":", 1)[1]] if ":" in line})
    name_servers = sorted({line.split(":", 1)[1].strip().lower().rstrip(".") for line in lines if re.match(r"\s*(name server|nserver)\s*:", line, re.I) and ":" in line})
    redacted_fields = sorted({key for key in ("registrant", "registrant organization", "registrant email") if any(key in line.lower() and ("redacted" in line.lower() or "privacy" in line.lower()) for line in lines)})
    privacy = bool(redacted_fields or any(marker in lowered for marker in ("privacy protect", "whois privacy", "domain privacy")))
    return {"status": "ok", "server": server, "source": source, "domain": host, "registrar": _find_value(lines, ("registrar", "registrar name")), "created": created, "updated": updated, "expires": expires, "status_codes": statuses, "name_servers": name_servers, "privacy": privacy, "redacted_fields": redacted_fields, "raw_lines_count": len(lines)}