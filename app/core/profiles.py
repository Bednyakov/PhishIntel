"""Analysis profiles shared by interactive and non-interactive entry points."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisProfile:
    name: str
    title: str
    description: str
    dynamic: bool = False
    search: bool = False
    active: bool = False
    javascript: bool = False


PROFILES = {
    "quick": AnalysisProfile("quick", "Быстрая проверка", "Базовые сетевые проверки без расширенных источников."),
    "full": AnalysisProfile("full", "Полный анализ", "Полный анализ домена с JavaScript, динамическим анализом и поисковой видимостью.", dynamic=True, javascript=True, search=True),
    "security": AnalysisProfile("security", "Аудит безопасности", "Расширенный аудит с динамическим анализом и активными сканерами.", dynamic=True, search=True, active=True, javascript=True),
}


def get_profile(name: str) -> AnalysisProfile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        choices = ", ".join(PROFILES)
        raise ValueError(f"unknown profile '{name}', choose one of: {choices}") from exc