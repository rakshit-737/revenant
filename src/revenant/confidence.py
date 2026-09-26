"""Confidence scorer (ACH / Admiralty-inspired).

A chain's confidence blends four signals, each in [0,1]:

* reliability   - mean source-reliability weight of its events
* corroboration - how many *distinct* source artifacts back the chain
* temporal_fit  - mean temporal tightness of its causal edges
* edge_strength - mean rule confidence of its edges

Tampering indicators apply a multiplicative penalty. The result maps to a
human-facing grade (LOW/MEDIUM/HIGH/CONFIRMED). Weights are explicit and
documented so the score is defensible, not a black box.
"""

from __future__ import annotations

from dataclasses import dataclass

from .graph import ProvenanceGraph
from .models import ConfidenceGrade, ProvenanceChain

WEIGHTS = {
    "reliability": 0.3,
    "corroboration": 0.3,
    "temporal_fit": 0.2,
    "edge_strength": 0.2,
}


@dataclass
class ConfidenceBreakdown:
    reliability: float
    corroboration: float
    temporal_fit: float
    edge_strength: float
    penalty: float
    score: float
    grade: ConfidenceGrade

    def as_dict(self) -> dict[str, float | str]:
        return {
            "reliability": round(self.reliability, 4),
            "corroboration": round(self.corroboration, 4),
            "temporal_fit": round(self.temporal_fit, 4),
            "edge_strength": round(self.edge_strength, 4),
            "penalty": round(self.penalty, 4),
            "score": round(self.score, 4),
            "grade": self.grade.value,
        }


def _corroboration_factor(distinct_sources: int) -> float:
    # 1 source -> 0.4, 2 -> 0.7, 3 -> 0.9, 4+ -> ~1.0 (diminishing returns)
    table = {0: 0.0, 1: 0.4, 2: 0.7, 3: 0.9}
    return table.get(distinct_sources, 1.0)


def score_chain(chain: ProvenanceChain, graph: ProvenanceGraph) -> ConfidenceBreakdown:
    events = [graph.get_event(eid) for eid in chain.event_ids]
    events = [e for e in events if e is not None]

    if events:
        reliability = sum(e.source_reliability.weight for e in events) / len(events)
        distinct_sources = len({e.source_artifact for e in events})
    else:
        reliability = 0.0
        distinct_sources = 0
    corroboration = _corroboration_factor(distinct_sources)

    if chain.edges:
        edge_strength = sum(e.confidence for e in chain.edges) / len(chain.edges)
        # tightness recomputed from windows already folded into edge conf; use conf spread
        temporal_fit = sum(
            1.0 / (1.0 + e.time_delta_s / 600.0) for e in chain.edges
        ) / len(chain.edges)
    else:
        edge_strength = 0.0
        temporal_fit = 0.0

    base = (
        WEIGHTS["reliability"] * reliability
        + WEIGHTS["corroboration"] * corroboration
        + WEIGHTS["temporal_fit"] * temporal_fit
        + WEIGHTS["edge_strength"] * edge_strength
    )
    # each tampering flag knocks 20% off, floored so it never fully vanishes
    penalty = max(0.5, 1.0 - 0.2 * len(chain.tampering_flags)) if chain.tampering_flags else 1.0
    score = round(base * penalty, 4)
    return ConfidenceBreakdown(
        reliability=reliability,
        corroboration=corroboration,
        temporal_fit=temporal_fit,
        edge_strength=edge_strength,
        penalty=penalty,
        score=score,
        grade=ConfidenceGrade.from_score(score),
    )


def apply_score(chain: ProvenanceChain, graph: ProvenanceGraph) -> ProvenanceChain:
    b = score_chain(chain, graph)
    chain.confidence_score = b.score
    chain.grade = b.grade
    return chain
