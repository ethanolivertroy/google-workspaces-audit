"""Abstract base class for report generators."""

from __future__ import annotations

from abc import ABC, abstractmethod

from gws_inspector.models import ComplianceFinding, GWSData
from gws_inspector.output import OutputManager


class ReportGenerator(ABC):
    """Base class every report generator must subclass."""

    name: str
    display_name: str

    @abstractmethod
    def generate(
        self,
        findings: list[ComplianceFinding],
        data: GWSData,
        output: OutputManager,
    ) -> None:
        ...
