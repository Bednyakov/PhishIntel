"""Domain scanning tool and its profile-aware adapter."""

from dataclasses import dataclass
from typing import Callable

from ..core.profiles import AnalysisProfile, get_profile
from ..main import analyze


@dataclass(frozen=True)
class DomainScanOptions:
    target: str
    profile: str = "full"
    timeout: float = 8.0
    progress_callback: Callable[[dict], None] | None = None
    active_tools: tuple[str, ...] | None = None


def run(options: DomainScanOptions) -> dict:
    profile: AnalysisProfile = get_profile(options.profile)
    # None means all scanners. An empty tuple is preserved as an explicit
    # "do not run" value for non-security profiles and backwards compatibility.
    active_tools = options.active_tools if profile.active else ()
    return analyze(
        options.target,
        timeout=options.timeout,
        progress_callback=options.progress_callback,
        active_tools=active_tools,
        dynamic_analysis=profile.dynamic,
        search_analysis=profile.search,
        javascript_analysis=profile.javascript,
        thorough_active=profile.name == "security",
    )