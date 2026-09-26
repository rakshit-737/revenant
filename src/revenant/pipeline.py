"""End-to-end orchestration: raw records -> ranked, scored, annotated chains.

Ties the modules together and maintains the custody ledger across ingest and
reconstruction so every derived claim is traceable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .antiforensics import annotate_chain, scan
from .confidence import apply_score
from .graph import ProvenanceGraph
from .integrity import CustodyLedger
from .models import Event, ProvenanceChain, TamperingIndicator
from .normalize import normalize_batch
from .reconstruct import ChainReconstructor
from .rules import RuleEngine


@dataclass
class Analysis:
    events: list[Event]
    graph: ProvenanceGraph
    chains: list[ProvenanceChain]
    indicators: list[TamperingIndicator]
    ledger: CustodyLedger = field(default_factory=CustodyLedger)


def run(records: list[tuple[str, dict[str, Any]]], *, backend: str = "auto") -> Analysis:
    ledger = CustodyLedger()
    events = normalize_batch(records)
    for ev in events:
        ledger.record_ingest(ev)

    graph = ProvenanceGraph(backend=backend)
    graph.add_events(events)

    RuleEngine().infer(graph)
    indicators = scan(graph)

    chains = ChainReconstructor(graph).reconstruct()
    for chain in chains:
        annotate_chain(chain, indicators)
        apply_score(chain, graph)  # re-score now that tampering flags are set
    chains.sort(key=lambda c: c.confidence_score, reverse=True)

    ledger.append("reconstruct", digest=f"{len(chains)}chains")
    return Analysis(events=events, graph=graph, chains=chains, indicators=indicators, ledger=ledger)
