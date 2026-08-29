"""Registry of user-facing tools.

New OSINT modules should register a tool here rather than adding menu branches.
"""

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Tool:
    name: str
    title: str
    description: str
    run_interactive: Callable[[], Any]
    run_cli: Callable[[Any], Any]


_TOOLS: dict[str, Tool] = {}


def register(tool: Tool) -> Tool:
    if tool.name in _TOOLS:
        raise ValueError(f"tool already registered: {tool.name}")
    _TOOLS[tool.name] = tool
    return tool


def get(name: str) -> Tool:
    try:
        return _TOOLS[name]
    except KeyError as exc:
        raise ValueError(f"unknown tool: {name}") from exc


def all_tools() -> tuple[Tool, ...]:
    return tuple(_TOOLS.values())