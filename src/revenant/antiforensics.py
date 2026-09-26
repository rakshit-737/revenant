"""Anti-forensics indicators (research-flavored, Grade D — see TODO).

Rather than trusting timestamps blindly, REVENANT flags cross-artifact
inconsistencies as *tampering indicators* that lower a chain's confidence:

* timestomp    - an event carries conflicting MFT vs $LogFile times
* hash_mismatch- an event's stored integrity hash no longer matches content
* log_gap      - a silent window with no artifacts (reported as 'unknown',
                 never fabricated)
"""

from __future__ import annotations

from .graph import ProvenanceGraph
from .integrity import verify_event
from .models import Event, ProvenanceChain, TamperingIndicator


def detect_timestomp(events: list[Event]) -> list[TamperingIndicator]:
    out: list[TamperingIndicator] = []
    for e in events:
        mft = e.attributes.get("mft_time")
        logf = e.attributes.get("logfile_time")
        if mft and logf and mft != logf:
            out.append(
                TamperingIndicator(
                    indicator="timestomp",
                    detail=f"MFT time {mft} disagrees with $LogFile time {logf} for {e.object}",
                    event_ids=[e.event_id],
                    severity="high",
                )
            )
    return out


def detect_hash_mismatch(events: list[Event]) -> list[TamperingIndicator]:
    out: list[TamperingIndicator] = []
    for e in events:
        if e.integrity_hash and not verify_event(e):
            out.append(
                TamperingIndicator(
                    indicator="hash_mismatch",
                    detail=f"integrity hash mismatch for {e.event_id}",
                    event_ids=[e.event_id],
                    severity="high",
                )
            )
    return out


def detect_log_gaps(events: list[Event], gap_threshold_s: float = 1200.0) -> list[TamperingIndicator]:
    out: list[TamperingIndicator] = []
    ordered = sorted(events, key=lambda e: e.timestamp)
    for a, b in zip(ordered, ordered[1:]):
        delta = (b.timestamp - a.timestamp).total_seconds()
        if delta > gap_threshold_s:
            out.append(
                TamperingIndicator(
                    indicator="log_gap",
                    detail=f"no artifacts for {int(delta)}s between {a.event_id} and {b.event_id} (unknown)",
                    event_ids=[a.event_id, b.event_id],
                    severity="medium",
                )
            )
    return out


def scan(graph: ProvenanceGraph, *, gap_threshold_s: float = 1200.0) -> list[TamperingIndicator]:
    events = graph.events
    return (
        detect_timestomp(events)
        + detect_hash_mismatch(events)
        + detect_log_gaps(events, gap_threshold_s)
    )


def annotate_chain(chain: ProvenanceChain, indicators: list[TamperingIndicator]) -> ProvenanceChain:
    """Attach any indicators whose events fall in the chain."""
    chain_events = set(chain.event_ids)
    flags = [
        f"{ind.indicator}: {ind.detail}"
        for ind in indicators
        if chain_events.intersection(ind.event_ids)
    ]
    chain.tampering_flags = flags
    return chain
