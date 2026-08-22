"""Domain-level heuristics."""

from .common import normalize_target


def analyze(target: str) -> dict:
    host, _ = normalize_target(target)
    labels = host.split(".")
    suspicious_terms = ("login", "secure", "verify", "account", "update", "support", "wallet")
    found = [term for term in suspicious_terms if term in host]
    return {"status": "ok", "domain": host, "tld": labels[-1], "labels": labels, "length": len(host), "suspicious_terms": found, "is_subdomain": len(labels) > 2}
