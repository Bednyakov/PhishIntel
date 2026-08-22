"""Normalized report structures used by the analyzers and CLI."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Indicator:
    name: str
    severity: str
    description: str
    evidence: Any = None

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "severity": self.severity, "description": self.description, "evidence": self.evidence}


@dataclass
class Report:
    target: str
    results: dict[str, Any] = field(default_factory=dict)
    indicators: list[dict[str, Any]] = field(default_factory=list)
    risk: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        output: dict[str, Any] = {"target": self.target}
        output.update(self.results)
        output["indicators"] = self.indicators
        output["risk"] = self.risk
        return output
