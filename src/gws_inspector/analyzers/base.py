"""Abstract base class for framework analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from gws_inspector.models import ComplianceFinding, GWSData


class FrameworkAnalyzer(ABC):
    """Base class every compliance framework analyzer must subclass."""

    name: str
    display_name: str

    @abstractmethod
    def analyze(self, data: GWSData) -> list[ComplianceFinding]:
        ...
