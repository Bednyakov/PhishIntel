"""Small JSON-backed localization layer for interactive UI and reports."""

from __future__ import annotations

import contextvars
import json
from pathlib import Path
from typing import Any

SUPPORTED_LOCALES = ("en", "ru")
DEFAULT_LOCALE = "ru"
_current_locale: contextvars.ContextVar[str] = contextvars.ContextVar("phishintel_locale", default=DEFAULT_LOCALE)
_translations = json.loads((Path(__file__).with_name("locales.json")).read_text(encoding="utf-8"))


def normalize_locale(locale: str | None) -> str:
    return locale if locale in SUPPORTED_LOCALES else DEFAULT_LOCALE


def set_locale(locale: str) -> None:
    _current_locale.set(normalize_locale(locale))


def get_locale() -> str:
    return _current_locale.get()


def translate(key: str, **values: Any) -> str:
    locale = get_locale()
    template = _translations.get(locale, {}).get(key) or _translations[DEFAULT_LOCALE].get(key, key)
    return template.format(**values)


class LocaleContext:
    def __init__(self, locale: str) -> None:
        self.locale = normalize_locale(locale)
        self._token: contextvars.Token[str] | None = None

    def __enter__(self) -> "LocaleContext":
        self._token = _current_locale.set(self.locale)
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self._token is not None:
            _current_locale.reset(self._token)


def tr(key: str, **values: Any) -> str:
    return translate(key, **values)