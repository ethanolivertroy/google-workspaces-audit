"""Report generator registry."""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gws_inspector.reporters.base import ReportGenerator

_REPORTER_REGISTRY: dict[str, type[ReportGenerator]] = {}
_modules_loaded = False


def register_reporter(cls: type[ReportGenerator]) -> type[ReportGenerator]:
    _REPORTER_REGISTRY[cls.name] = cls
    return cls


def _ensure_loaded() -> None:
    global _modules_loaded
    if _modules_loaded:
        return
    _modules_loaded = True
    package = importlib.import_module(__name__)
    for info in pkgutil.iter_modules(package.__path__):
        if info.name != "base":
            importlib.import_module(f"{__name__}.{info.name}")


def get_reporters(names: list[str] | None = None) -> list[ReportGenerator]:
    _ensure_loaded()
    if names is None:
        return [cls() for cls in _REPORTER_REGISTRY.values()]
    return [_REPORTER_REGISTRY[n]() for n in names if n in _REPORTER_REGISTRY]
