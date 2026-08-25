"""DNS resolution analyzer using the standard library."""

import shutil
import socket
import subprocess

from .common import normalize_target, unavailable


def _lookup(host: str, record: str) -> list[str]:
    if not shutil.which("nslookup"):
        return []
    try:
        output = subprocess.run(["nslookup", f"-type={record}", host], capture_output=True, text=True, timeout=5, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    values = []
    for line in output.splitlines():
        if "=" in line:
            value = line.split("=", 1)[1].strip().rstrip(".")
            if value and value.lower() != "unknown":
                values.append(value)
    return sorted(set(values))


def analyze(target: str) -> dict:
    host, _ = normalize_target(target)
    result = {"status": "ok", "a": [], "aaaa": [], "cname": _lookup(host, "CNAME"), "mx": _lookup(host, "MX"), "ns": _lookup(host, "NS"), "txt": _lookup(host, "TXT"), "caa": _lookup(host, "CAA"), "soa": {}}
    try:
        info = socket.getaddrinfo(host, None)
        result["a"] = sorted({item[4][0] for item in info if ":" not in item[4][0]})
        result["aaaa"] = sorted({item[4][0] for item in info if ":" in item[4][0]})
        return result
    except OSError as exc:
        return {**result, "status": "unavailable", "error": str(exc)}


def analyze_ip(dns_result: dict) -> dict:
    addresses = sorted(set(dns_result.get("a", []) + dns_result.get("aaaa", [])))
    address = (addresses or [None])[0]
    if not address:
        return {"status": "unavailable", "address": None, "addresses": [], "version": None, "asn": None, "organization": None, "country": None, "city": None, "reverse_dns": None}
    try:
        reverse = socket.gethostbyaddr(address)[0]
    except (OSError, socket.herror):
        reverse = None
    return {"status": "ok", "address": address, "addresses": addresses, "version": 6 if ":" in address else 4, "asn": None, "organization": None, "country": None, "city": None, "reverse_dns": reverse}
