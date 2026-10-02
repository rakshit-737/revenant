"""Confidence scorer (Admiralty-inspired source reliability).

A chain's confidence is a weighted *sum* of four signals, each in [0,1]:

* reliability   - mean source-reliability weight of its events
* corroboration - how many *distinct* source artifacts back the chain,
                  counting cross-artefact corroborations found by fusion
* temporal_fit  - mean temporal tightness of its causal edges
* edge_strength - mean rule confidence of its edges

Tampering indicators apply a multiplicative penalty. The result maps to a
human-facing grade (LOW/MEDIUM/HIGH/CONFIRMED). Weights and grade cut-offs
are explicit, hand-set and documented so the score is defensible, not a black
box. Only the per-rule edge confidences feeding ``edge_strength`` are
calibrated against ground truth; the story score itself is not a calibrated
probability.
"""

from __future__ import annotations

from dataclasses import dataclass

from .graph import ProvenanceGraph
from .models import ConfidenceGrade, IncidentStory, ProvenanceChain

WEIGHTS = {
    "reliability": 0.3,
    "corroboration": 0.3,
    "temporal_fit": 0.2,
    "edge_strength": 0.2,
}


@dataclass
class ConfidenceBreakdown:
    """Every term of a story/chain confidence score, for the report and the UI.

    Attributes
    ----------
    reliability, corroboration, temporal_fit, edge_strength
        The four weighted terms, each in [0, 1].
    penalty
        Multiplicative tampering penalty (1.0 = none, floored at 0.5).
    score
        ``penalty * sum(WEIGHTS[k] * term_k)``.
    grade
        ``score`` mapped through the hand-set cut-offs.
    """

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


def score_chain(chain: ProvenanceChain | IncidentStory, graph: ProvenanceGraph) -> ConfidenceBreakdown:
    """Score a chain or story against the provenance graph it came from.

    Parameters
    ----------
    chain
        A path-view chain or an incident story (its ``event_ids``, ``edges`` and
        ``tampering_flags`` are read).
    graph
        The graph holding the events, used for reliability and corroborating sources.

    Returns
    -------
    ConfidenceBreakdown
        All terms plus the final score and grade.
    """
    events = [graph.get_event(eid) for eid in chain.event_ids]
    events = [e for e in events if e is not None]

    if events:
        reliability = sum(e.source_reliability.weight for e in events) / len(events)
        sources: set[str] = set()
        for e in events:
            sources |= graph.sources_for(e.event_id)
        distinct_sources = len(sources)
    else:
        reliability = 0.0
        distinct_sources = 0
    corroboration = _corroboration_factor(distinct_sources)

    if chain.edges:
        edge_strength = sum(e.confidence for e in chain.edges) / len(chain.edges)
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


def apply_score(chain: ProvenanceChain | IncidentStory, graph: ProvenanceGraph) -> ProvenanceChain | IncidentStory:
    """Compute `score_chain` and store the score and grade on ``chain`` (returned)."""
    b = score_chain(chain, graph)
    chain.confidence_score = b.score
    chain.grade = b.grade
    return chain
