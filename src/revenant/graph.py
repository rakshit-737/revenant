"""Temporal provenance graph.

Backed by networkx when available (default), with a tiny in-memory fallback so
the core runs with zero third-party deps and never requires Neo4j/Docker at
runtime. Nodes are events (keyed by event_id); edges are typed causal links.
"""

from __future__ import annotations

from typing import Iterable, Optional

from .models import CausalEdge, Event

try:  # pragma: no cover - exercised implicitly
    import networkx as nx

    _HAVE_NX = True
except Exception:  # pragma: no cover
    _HAVE_NX = False


class ProvenanceGraph:
    """Directed temporal graph of forensic events and causal edges."""

    def __init__(self, backend: str = "auto") -> None:
        if backend == "networkx" and not _HAVE_NX:
            raise RuntimeError("networkx backend requested but not installed")
        self.backend = "networkx" if (backend in ("auto", "networkx") and _HAVE_NX) else "memory"
        self._events: dict[str, Event] = {}
        self._edges: list[CausalEdge] = []
        self._g = nx.DiGraph() if self.backend == "networkx" else None

    # -- nodes -------------------------------------------------------------- #
    def add_event(self, event: Event) -> None:
        self._events[event.event_id] = event
        if self._g is not None:
            self._g.add_node(event.event_id, ts=event.timestamp)

    def add_events(self, events: Iterable[Event]) -> None:
        for e in events:
            self.add_event(e)

    def get_event(self, event_id: str) -> Optional[Event]:
        return self._events.get(event_id)

    @property
    def events(self) -> list[Event]:
        return sorted(self._events.values(), key=lambda e: e.timestamp)

    # -- edges -------------------------------------------------------------- #
    def add_edge(self, edge: CausalEdge) -> None:
        if edge.src_event_id not in self._events or edge.dst_event_id not in self._events:
            raise KeyError("edge references unknown event")
        self._edges.append(edge)
        if self._g is not None:
            self._g.add_edge(edge.src_event_id, edge.dst_event_id, relation=edge.relation)

    @property
    def edges(self) -> list[CausalEdge]:
        return list(self._edges)

    def successors(self, event_id: str) -> list[str]:
        return [e.dst_event_id for e in self._edges if e.src_event_id == event_id]

    def predecessors(self, event_id: str) -> list[str]:
        return [e.src_event_id for e in self._edges if e.dst_event_id == event_id]

    def out_edges(self, event_id: str) -> list[CausalEdge]:
        return [e for e in self._edges if e.src_event_id == event_id]

    def roots(self) -> list[str]:
        """Events with no incoming causal edge (candidate chain starts)."""
        has_incoming = {e.dst_event_id for e in self._edges}
        return [eid for eid in self._events if eid not in has_incoming]

    def __len__(self) -> int:
        return len(self._events)
