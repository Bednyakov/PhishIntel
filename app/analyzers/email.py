"""Local email-address validation and mail-domain intelligence.

The analyzer intentionally does not use breach, enrichment, or account
enumeration APIs.  It combines syntax checks, bundled MailAccess-derived
corpora, local resource rules, and ordinary DNS lookups.  SMTP probing is an
explicit opt-in because it creates traffic to a third-party mail server and
is not proof that a mailbox exists.
"""
from __future__ import annotations

import json
import re
import smtplib
import socket
from pathlib import Path
from typing import Any, Callable

DEFAULT_RULES = Path(__file__).resolve().parents[2] / "wordlists" / "email_rules.json"
DEFAULT_DISPOSABLE = Path(__file__).resolve().parents[2] / "wordlists" / "disposable_email_domains.json"

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{0,63}@[A-Za-z0-9]"
    r"[A-Za-z0-9.-]{0,252}\.[A-Za-z]{2,63}$"
)
ROLE_PREFIXES = frozenset(
    "admin administrator billing contact devinfo help hello info office postmaster privacy"
    " sales security support team webmaster abuse noreply no-reply do-not-reply bounce"
    .split()
)


def load_rules(path: str | Path = DEFAULT_RULES) -> list[dict[str, Any]]:
    """Load local domain-specific rules; a missing file is an empty catalog."""
    rules_path = Path(path)
    if not rules_path.is_file():
        return []
    payload = json.loads(rules_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict) and isinstance(item.get("domain"), str)]


def load_disposable_domains(path: str | Path = DEFAULT_DISPOSABLE) -> frozenset[str]:
    """Read the bundled MailAccess disposable-domain corpus."""
    domains_path = Path(path)
    if not domains_path.is_file():
        return frozenset()
    payload = json.loads(domains_path.read_text(encoding="utf-8"))
    return frozenset(item.strip().lower() for item in payload if isinstance(item, str) and item.strip())


def normalize_email(value: str) -> str:
    """Normalize and validate an email address without DNS or network access."""
    if not isinstance(value, str):
        raise ValueError("email must be a string")
    email = value.strip().lower()
    if not email or any(char.isspace() for char in email) or email.count("@") != 1:
        raise ValueError("email must contain one @ and no whitespace")
    local, domain = email.rsplit("@", 1)
    if len(local) > 64 or len(domain) > 253 or local.startswith(".") or local.endswith(".") or ".." in local:
        raise ValueError("email has an invalid local part")
    if not EMAIL_RE.fullmatch(email) or ".." in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("email has an invalid syntax")
    return email


def _role(local: str) -> tuple[bool, str | None]:
    if local in ROLE_PREFIXES:
        return True, "exact"
    prefix = re.split(r"[._+\-]", local, maxsplit=1)[0]
    if prefix in ROLE_PREFIXES:
        return True, "prefix"
    return False, None


def _dns_records(domain: str, resolver: Callable[[str, int], list[tuple[Any, ...]]] | None) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {"mx": [], "a": [], "aaaa": [], "txt": []}
    if resolver is None:
        def resolver(host: str, port: int) -> list[tuple[Any, ...]]:
            return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    try:
        records["a"] = sorted({item[4][0] for item in resolver(domain, 0) if ":" not in item[4][0]})
        records["aaaa"] = sorted({item[4][0] for item in resolver(domain, 0) if ":" in item[4][0]})
    except (OSError, socket.gaierror):
        pass
    # MX/TXT are deliberately resolved through nslookup when available.  This
    # keeps the base project dependency-free and makes failures non-fatal.
    try:
        import shutil
        import subprocess
        if shutil.which("nslookup"):
            for record in ("MX", "TXT"):
                output = subprocess.run(["nslookup", f"-type={record}", domain], capture_output=True, text=True, timeout=5, check=False).stdout
                values = []
                for line in output.splitlines():
                    if "=" in line:
                        value = line.split("=", 1)[1].strip().strip('"').rstrip(".")
                        if value and value.lower() != "unknown":
                            values.append(value)
                records[record.lower()] = sorted(set(values))
    except (OSError, subprocess.TimeoutExpired):
        pass
    return records


def _smtp_probe(email: str, mx_hosts: list[str], timeout: float) -> dict[str, Any]:
    if not mx_hosts:
        return {"status": "unavailable", "reason": "mx_missing"}
    host = mx_hosts[0].split()[-1].rstrip(".")
    try:
        with smtplib.SMTP(host, 25, timeout=timeout) as client:
            client.helo("phishintel.local")
            client.mail("postmaster@phishintel.local")
            code, message = client.rcpt(email)
        if 200 <= code < 300:
            status = "accepted"
        elif code in (450, 451, 452):
            status = "greylisted"
        elif code in (550, 551, 552, 553, 554):
            status = "rejected"
        else:
            status = "uncertain"
        return {"status": status, "smtp_code": code, "message": message.decode(errors="replace") if isinstance(message, bytes) else str(message), "mx_host": host}
    except (OSError, smtplib.SMTPException) as exc:
        return {"status": "error", "error": str(exc), "mx_host": host}


def analyze(email: str, timeout: float = 8.0, rules: str | Path = DEFAULT_RULES, disposable: str | Path = DEFAULT_DISPOSABLE, check_smtp: bool = False, resolver: Callable[[str, int], list[tuple[Any, ...]]] | None = None) -> dict[str, Any]:
    normalized = normalize_email(email)
    local, domain = normalized.rsplit("@", 1)
    disposable_domains = load_disposable_domains(disposable)
    role, role_type = _role(local)
    dns = _dns_records(domain, resolver)
    domain_rules = [rule for rule in load_rules(rules) if rule["domain"].lower() == domain]
    matched_rules = [rule.get("name", rule["domain"]) for rule in domain_rules]
    reasons: list[str] = []
    if domain in disposable_domains:
        reasons.append("disposable_domain")
    if role:
        reasons.append(f"role:{role_type}")
    if dns["mx"]:
        reasons.append("mx_present")
    else:
        reasons.append("mx_missing")
    smtp = _smtp_probe(normalized, dns["mx"], timeout) if check_smtp else {"status": "not_checked"}
    return {
        "tool": "email-check",
        "target": normalized,
        "query": {"email": normalized},
        "sources": {"rules": str(rules), "disposable_domains": str(disposable), "external_apis": []},
        "email": {"address": normalized, "local_part": local, "domain": domain, "syntax_valid": True, "disposable": domain in disposable_domains, "is_role": role, "role_match_type": role_type},
        "dns": dns,
        "rules": {"matched": matched_rules, "count": len(matched_rules)},
        "smtp": smtp,
        "summary": {"status": "disposable" if domain in disposable_domains else ("role" if role else ("mx_valid" if dns["mx"] else "mx_missing")), "reasons": reasons},
    }