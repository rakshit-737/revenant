"""REVENANT — evidence-graph forensic timeline reconstruction (lab-only).

The package namespace is lazy: ``import revenant`` (and so ``revenant --version``
or ``--help``) does not import pydantic, networkx or the engine until a name such
as `revenant.run` or `revenant.Event` is first used.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

__version__ = "1.1.3"

_LAZY = {
    "Analysis": "pipeline", "run": "pipeline",
    "ConfidenceGrade": "models", "Event": "models", "EventType": "models", "KillChainStage": "models",
    "ProvenanceChain": "models", "SourceReliability": "models",
}

if TYPE_CHECKING:  # pragma: no cover
    from .models import ConfidenceGrade, Event, EventType, KillChainStage, ProvenanceChain, SourceReliability
    from .pipeline import Analysis, run


def __getattr__(name: str) -> Any:
    """Import public names on first use (PEP 562)."""
    mod = _LAZY.get(name)
    if mod is None:
        raise AttributeError(f"module 'revenant' has no attribute {name!r}")
    value = getattr(importlib.import_module(f".{mod}", __name__), name)
    globals()[name] = value
    return value


__all__ = [
    "Analysis",
    "ConfidenceGrade",
    "Event",
    "EventType",
    "KillChainStage",
    "ProvenanceChain",
    "SourceReliability",
    "run",
    "__version__",
]
