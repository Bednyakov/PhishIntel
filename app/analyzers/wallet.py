"""Cryptocurrency wallet identification and optional blockchain intelligence."""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Any

import requests

_HEX_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BTC_BASE58 = re.compile(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$")
_BTC_BECH32 = re.compile(r"^(bc1|tb1)[ac-hj-np-z02-9]{11,87}$", re.IGNORECASE)
_SOLANA = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_TRON = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")


def _base58_decode(value: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    for char in value:
        number = number * 58 + alphabet.index(char)
    return b"\0" * (len(value) - len(value.lstrip("1"))) + (number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b"")


def _valid_base58check(value: str, prefix: int | None = None) -> bool:
    try:
        decoded = _base58_decode(value)
    except (ValueError, IndexError):
        return False
    return len(decoded) == 25 and (prefix is None or decoded[0] == prefix) and hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()[:4] == decoded[-4:]


def identify(address: str) -> dict[str, Any]:
    value = address.strip()
    if _HEX_ADDRESS.fullmatch(value):
        return {"blockchain": "ethereum", "address_type": "evm", "valid": True, "normalized_address": value.lower()}
    if _BTC_BECH32.fullmatch(value):
        return {"blockchain": "bitcoin", "address_type": "bech32", "valid": True, "normalized_address": value.lower()}
    if _BTC_BASE58.fullmatch(value):
        return {"blockchain": "bitcoin", "address_type": "legacy_or_p2sh", "valid": _valid_base58check(value), "normalized_address": value}
    if _TRON.fullmatch(value):
        return {"blockchain": "tron", "address_type": "base58check", "valid": _valid_base58check(value, 0x41), "normalized_address": value}
    if _SOLANA.fullmatch(value):
        try:
            valid = len(_base58_decode(value)) == 32
        except (ValueError, IndexError):
            valid = False
        return {"blockchain": "solana", "address_type": "base58", "valid": valid, "normalized_address": value}
    return {"blockchain": None, "address_type": None, "valid": False, "normalized_address": value}


def _empty_metrics() -> dict[str, Any]:
    return {"first_activity": None, "last_activity": None, "transaction_count": None, "incoming_volume": None, "outgoing_volume": None, "current_balance": None, "counterparties": None, "token_count": None, "activity": {"24h": None, "7d": None, "30d": None}, "approximate_usd_volume": None}


def _blockchair(address: str, blockchain: str, timeout: float) -> tuple[dict[str, Any], dict[str, Any]]:
    metrics = _empty_metrics()
    if blockchain not in {"bitcoin", "ethereum"}:
        return metrics, {"status": "not_supported", "provider": "blockchair"}
    api_key = os.getenv("PHISHINTEL_BLOCKCHAIR_KEY")
    endpoint = f"https://api.blockchair.com/{blockchain}/dashboards/address/{address}"
    if api_key:
        endpoint += f"?key={api_key}"
    try:
        response = requests.get(endpoint, timeout=timeout, headers={"User-Agent": "phishintel/1.0"})
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data", {})
        row = data.get(address) or data.get(address.lower()) or {}
        address_data = row.get("address", row)
        metrics.update({"transaction_count": address_data.get("transaction_count"), "current_balance": address_data.get("balance"), "counterparties": address_data.get("counterparty_count"), "token_count": address_data.get("token_count"), "first_activity": address_data.get("first_seen_receiving") or address_data.get("first_seen"), "last_activity": address_data.get("last_seen")})
        return metrics, {"status": "ok", "provider": "blockchair", "api_key_configured": bool(api_key)}
    except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
        return metrics, {"status": "unavailable", "provider": "blockchair", "error": str(exc), "api_key_configured": bool(api_key)}


def analyze(address: str, timeout: float = 8.0) -> dict[str, Any]:
    if not isinstance(address, str) or not address.strip():
        raise ValueError("wallet address must not be empty")
    identity = identify(address)
    report = {"tool": "wallet-check", "target": address.strip(), **identity, "metrics": _empty_metrics(), "source": {"status": "not_requested", "provider": "blockchair"}, "observed_at": datetime.now(timezone.utc).isoformat()}
    if identity["valid"]:
        report["metrics"], report["source"] = _blockchair(identity["normalized_address"], identity["blockchain"], timeout)
    return report