"""Court-style report generator.

Emits a Markdown report: ranked narratives with per-hop evidence and integrity
hashes, a chain-of-custody summary, and an explicit *what-remains-uncertain*
section. Every narrative sentence cites a graph node (event id) so no claim is
unsupported. No PDF dependency at runtime (Grade A markdown; WeasyPrint PDF is
a documented TODO).
"""

from __future__ import annotations

from .graph import ProvenanceGraph
from .models import ProvenanceChain
from .pipeline import Analysis


def _hop_line(graph: ProvenanceGraph, event_id: str) -> str:
    e = graph.get_event(event_id)
    if e is None:
        return f"- [{event_id}] (missing event)"
    h = (e.integrity_hash or "")[:12]
    return (
        f"- `{e.event_id}` {e.timestamp.isoformat()} - **{e.actor}** {e.action} "
        f"*{e.object}* (source: {e.source_artifact}/{e.source_reliability.value}, "
        f"sha256:{h}...)"
    )


def narrative_for(chain: ProvenanceChain, graph: ProvenanceGraph) -> str:
    lines: list[str] = []
    stages = " -> ".join(s.value for s in chain.stages) or "n/a"
    lines.append(f"### {chain.chain_id} - {chain.grade.value} (score {chain.confidence_score})")
    lines.append(f"**Kill-chain stages:** {stages}")
    lines.append("")
    lines.append("**Evidence (each hop cites its artifact + hash):**")
    for eid in chain.event_ids:
        lines.append(_hop_line(graph, eid))
    if chain.tampering_flags:
        lines.append("")
        lines.append("**Tampering indicators (confidence reduced):**")
        for f in chain.tampering_flags:
            lines.append(f"- {f}")
    return "\n".join(lines)


def generate_report(analysis: Analysis, *, top: int = 5) -> str:
    g = analysis.graph
    parts: list[str] = []
    parts.append("# REVENANT - Forensic Reconstruction Report")
    parts.append("")
    parts.append("> Lab-only analysis. Automatically generated; every claim links to evidence.")
    parts.append("")
    parts.append("## Summary")
    parts.append(f"- Events ingested: {len(analysis.events)}")
    parts.append(f"- Causal edges inferred: {len(g.edges)}")
    parts.append(f"- Candidate chains: {len(analysis.chains)}")
    parts.append(f"- Tampering indicators: {len(analysis.indicators)}")
    parts.append(f"- Custody ledger verified: {analysis.ledger.verify()}")
    parts.append("")

    parts.append("## Ranked incident narratives")
    if not analysis.chains:
        parts.append("_No causal chains reconstructed._")
    for chain in analysis.chains[:top]:
        parts.append("")
        parts.append(narrative_for(chain, g))

    parts.append("")
    parts.append("## What remains uncertain")
    gaps = [i for i in analysis.indicators if i.indicator == "log_gap"]
    if gaps:
        for gap in gaps:
            parts.append(f"- {gap.detail}")
    else:
        parts.append("- No unexplained timeline gaps above threshold were detected.")
    parts.append(
        "- Causal edges are rule-inferred correlations under temporal/entity "
        "constraints, not proof of intent."
    )
    parts.append(
        "- Confidence grades derive from source reliability, corroboration, and "
        "temporal fit; they are calibrated estimates, not certainties."
    )

    parts.append("")
    parts.append("## Chain of custody")
    parts.append(f"- Ledger records: {len(analysis.ledger.records)}")
    parts.append(f"- Tamper-evident hash chain intact: {analysis.ledger.verify()}")
    return "\n".join(parts)
