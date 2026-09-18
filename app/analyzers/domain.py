"""Domain-level heuristics."""

from .common import normalize_target


def analyze(target: str) -> dict:
    host, _ = normalize_target(target)
    try:
        import ipaddress
        address = ipaddress.ip_address(host)
        return {"status": "ok", "domain": host, "type": "ip", "version": address.version, "labels": [], "length": len(host), "suspicious_terms": [], "is_subdomain": False}
    except ValueError:
        pass
    labels = host.split(".")
    suspicious_terms = ("login", "secure", "verify", "account", "update", "support", "wallet")
    found = [term for term in suspicious_terms if term in host]
    return {"status": "ok", "domain": host, "tld": labels[-1], "labels": labels, "length": len(host), "suspicious_terms": found, "is_subdomain": len(labels) > 2}
