"""TLS certificate and protocol analyzer."""

import socket
import ssl

from .common import normalize_target, unavailable


def analyze(target: str, timeout: float = 8.0) -> dict:
    host, _ = normalize_target(target)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            # IP literals generally have no matching DNS SAN. Omitting SNI is
            # required for IPv6/IP targets; hostname targets retain SNI.
            server_name = None
            try:
                import ipaddress
                ipaddress.ip_address(host)
            except ValueError:
                server_name = host
            with context.wrap_socket(raw, server_hostname=server_name) as connection:
                certificate = connection.getpeercert()
                return {"status": "ok", "version": connection.version(), "cipher": connection.cipher()[0] if connection.cipher() else None, "subject": certificate.get("subject"), "issuer": certificate.get("issuer"), "not_before": certificate.get("notBefore"), "not_after": certificate.get("notAfter")}
    except (OSError, ssl.SSLError) as exc:
        return unavailable(exc)
