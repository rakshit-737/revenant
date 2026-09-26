"""Temporal provenance graph.

Backed by networkx when available (default), with an in-memory fallback so
the core runs with zero third-party graph deps and never requires
Neo4j/Docker at runtime. Nodes are events (keyed by event_id); edges are
typed causal links. Adjacency is indexed both ways so traversal is O(degree),
which matters on real captures with tens of thousands of events.

Corroboration (the same fact seen by several independent artefacts) is kept
*beside* the causal structure: a corroborated event keeps one primary node,
and its duplicates are recorded in ``corroborations`` and marked
``shadowed`` so rules never link through them twice.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

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
        self._out: dict[str, list[CausalEdge]] = defaultdict(list)
        self._in: dict[str, list[CausalEdge]] = defaultdict(list)
        self._sorted: list[Event] | None = None
        self._g = nx.DiGraph() if self.backend == "networkx" else None
        # primary event id -> ids of corroborating events from other artefacts
        self.corroborations: dict[str, list[str]] = defaultdict(list)
        self.shadowed: set[str] = set()

    # -- nodes -------------------------------------------------------------- #
    def add_event(self, event: Event) -> None:
        self._events[event.event_id] = event
        self._sorted = None
        if self._g is not None:
            self._g.add_node(event.event_id, ts=event.timestamp)

    def add_events(self, events: Iterable[Event]) -> None:
        for e in events:
            self.add_event(e)

    def get_event(self, event_id: str) -> Event | None:
        return self._events.get(event_id)

    @property
    def events(self) -> list[Event]:
        if self._sorted is None:
            self._sorted = sorted(self._events.values(), key=lambda e: (e.timestamp, e.event_id))
        return list(self._sorted)

    # -- corroboration ------------------------------------------------------ #
    def add_corroboration(self, primary_id: str, other_id: str) -> None:
        if primary_id not in self._events or other_id not in self._events:
            raise KeyError("corroboration references unknown event")
        if other_id not in self.corroborations[primary_id]:
            self.corroborations[primary_id].append(other_id)
        self.shadowed.add(other_id)

    def sources_for(self, event_id: str) -> set[str]:
        """Distinct artefact sources that attest to ``event_id``."""
        ev = self._events.get(event_id)
        if ev is None:
            return set()
        out = {ev.source_artifact}
        for oid in self.corroborations.get(event_id, []):
            o = self._events.get(oid)
            if o is not None:
                out.add(o.source_artifact)
        return out

    # -- edges -------------------------------------------------------------- #
    def add_edge(self, edge: CausalEdge) -> None:
        if edge.src_event_id not in self._events or edge.dst_event_id not in self._events:
            raise KeyError("edge references unknown event")
        self._edges.append(edge)
        self._out[edge.src_event_id].append(edge)
        self._in[edge.dst_event_id].append(edge)
        if self._g is not None:
            self._g.add_edge(edge.src_event_id, edge.dst_event_id, relation=edge.relation)

    @property
    def edges(self) -> list[CausalEdge]:
        return list(self._edges)

    def successors(self, event_id: str) -> list[str]:
        return [e.dst_event_id for e in self._out.get(event_id, [])]

    def predecessors(self, event_id: str) -> list[str]:
        return [e.src_event_id for e in self._in.get(event_id, [])]

    def out_edges(self, event_id: str) -> list[CausalEdge]:
        return list(self._out.get(event_id, []))

    def in_edges(self, event_id: str) -> list[CausalEdge]:
        return list(self._in.get(event_id, []))

    def has_incoming(self, event_id: str) -> bool:
        return bool(self._in.get(event_id))

    def roots(self) -> list[str]:
        """Events with no incoming causal edge (candidate chain starts)."""
        return [eid for eid in self._events if not self._in.get(eid) and eid not in self.shadowed]

    def descendants(self, event_id: str) -> set[str]:
        seen: set[str] = set()
        stack = [event_id]
        while stack:
            n = stack.pop()
            for s in self.successors(n):
                if s not in seen:
                    seen.add(s)
                    stack.append(s)
        return seen

    def ancestors(self, event_id: str) -> set[str]:
        seen: set[str] = set()
        stack = [event_id]
        while stack:
            n = stack.pop()
            for p in self.predecessors(n):
                if p not in seen:
                    seen.add(p)
                    stack.append(p)
        return seen

    def __len__(self) -> int:
        return len(self._events)
