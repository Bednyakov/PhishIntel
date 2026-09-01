"""Environment-backed application configuration."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv() -> None:
    path = ROOT / ".env"
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if value[:1] in {"'", '"'} and value[-1:] == value[:1]:
            value = value[1:-1]
        os.environ.setdefault(key, value)


_load_dotenv()


def env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def float_value(name: str, default: float) -> float:
    try:
        return float(env(name, str(default)))
    except ValueError:
        return default


def int_value(name: str, default: int) -> int:
    try:
        return int(env(name, str(default)))
    except ValueError:
        return default


def bool_value(name: str, default: bool = False) -> bool:
    return env(name, "true" if default else "false").lower() in {"1", "true", "yes", "y", "on"}


def list_value(name: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    value = env(name)
    return tuple(item.strip() for item in value.split(",") if item.strip()) if value else default