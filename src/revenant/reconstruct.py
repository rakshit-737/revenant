"""Chain reconstructor + kill-chain mapper.

Walks the provenance graph from root events along causal edges, enumerating
candidate incident chains (simple paths). Each event is mapped to a cyber
kill-chain stage; chains are then handed to the confidence scorer and returned
ranked by confidence.
"""

from __future__ import annotations

from .confidence import apply_score
from .graph import ProvenanceGraph
from .models import (
    CausalEdge,
    Event,
    EventType,
    KillChainStage,
    ProvenanceChain,
)

# event/relation -> kill-chain stage
_STAGE_BY_TYPE = {
    EventType.LOGON: KillChainStage.DELIVERY,
    EventType.PROCESS_START: KillChainStage.EXPLOITATION,
    EventType.REGISTRY_SET: KillChainStage.INSTALLATION,
    EventType.NETWORK_CONNECT: KillChainStage.C2,
    EventType.DNS_QUERY: KillChainStage.C2,
    EventType.FILE_WRITE: KillChainStage.ACTIONS,
    EventType.FILE_DELETE: KillChainStage.ACTIONS,
}


def stage_for(event: Event) -> KillChainStage | None:
    """Return the kill-chain stage of an event, or None."""
    return _STAGE_BY_TYPE.get(event.event_type)


def _stages_for_path(events: list[Event]) -> list[KillChainStage]:
    stages: list[KillChainStage] = []
    for e in events:
        s = stage_for(e)
        if s is not None and (not stages or stages[-1] != s):
            stages.append(s)
    return stages


class ChainReconstructor:
    def __init__(self, graph: ProvenanceGraph, *, max_depth: int = 12, min_length: int = 2):
        self.graph = graph
        self.max_depth = max_depth
        self.min_length = min_length

    def _edge_between(self, src_id: str, dst_id: str) -> CausalEdge | None:
        for e in self.graph.out_edges(src_id):
            if e.dst_event_id == dst_id:
                return e
        return None

    def _enumerate_paths(self, start: str) -> list[list[str]]:
        """DFS enumeration of simple paths; keeps only maximal paths."""
        paths: list[list[str]] = []

        def dfs(node: str, path: list[str], seen: set[str]) -> None:
            if len(path) > self.max_depth:
                paths.append(list(path))
                return
            succ = [s for s in self.graph.successors(node) if s not in seen]
            if not succ:
                paths.append(list(path))
                return
            for nxt in succ:
                seen.add(nxt)
                dfs(nxt, path + [nxt], seen)
                seen.discard(nxt)

        dfs(start, [start], {start})
        return paths

    def reconstruct(self) -> list[ProvenanceChain]:
        """Build de-duplicated provenance chains from every root of the graph."""
        chains: list[ProvenanceChain] = []
        seen_signatures: set[tuple[str, ...]] = set()
        counter = 0
        for root in self.graph.roots():
            for path in self._enumerate_paths(root):
                if len(path) < self.min_length:
                    continue
                sig = tuple(path)
                if sig in seen_signatures:
                    continue
                seen_signatures.add(sig)
                edges = []
                for a, b in zip(path, path[1:]):
                    e = self._edge_between(a, b)
                    if e:
                        edges.append(e)
                events = [self.graph.get_event(eid) for eid in path]
                events = [e for e in events if e]
                chain = ProvenanceChain(
                    chain_id=f"chain-{counter:04d}",
                    event_ids=path,
                    edges=edges,
                    stages=_stages_for_path(events),
                )
                apply_score(chain, self.graph)
                chains.append(chain)
                counter += 1
        chains.sort(key=lambda c: c.confidence_score, reverse=True)
        return chains
