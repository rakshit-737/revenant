"""Exports: JSON (API/UI), Cypher (Neo4j) and an optional live Neo4j push.

The engine stays in-memory (networkx); Neo4j is a *sink* for analysts who
want to explore the provenance graph in Neo4j Browser/Bloom. Export only
the part of the graph that carries meaning -- events inside stories plus
their edges -- so a 100k-event capture does not become a 100k-node dump.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from .stories import story_breakdown

if TYPE_CHECKING:  # pragma: no cover
    from .pipeline import Analysis


def _event_dict(analysis: Analysis, eid: str) -> dict[str, Any] | None:
    e = analysis.graph.get_event(eid)
    if e is None:
        return None
    t = analysis.tags.get(eid)
    return {
        "id": e.event_id,
        "time": e.timestamp.isoformat(),
        "type": e.event_type.value,
        "actor": e.actor,
        "action": e.action,
        "object": e.object,
        "source": e.source_artifact,
        "reliability": e.source_reliability.value,
        "hash": e.integrity_hash,
        "host": e.attributes.get("host", ""),
        "command_line": e.attributes.get("command_line", "")[:500],
        "techniques": sorted({x[0] for x in t.techniques}) if t else [],
        "suspicion": t.suspicion if t else 0.0,
        "corroborated_by": sorted(analysis.graph.sources_for(eid) - {e.source_artifact}),
    }


def story_event_ids(analysis: Analysis, top: int | None = None) -> list[str]:
    seen: dict[str, None] = {}
    for s in analysis.stories[:top]:
        for i in s.event_ids:
            seen.setdefault(i, None)
    return list(seen)


def to_dict(analysis: Analysis, *, top: int = 20, include_all_events: bool = False,
            max_events: int = 5000) -> dict[str, Any]:
    """JSON-able view of an analysis: stories with their events and edges.

    Parameters
    ----------
    analysis
        Result of `revenant.pipeline.run` or `revenant.pipeline.analyze_paths`.
    top
        Number of ranked stories to include.
    include_all_events
        Also include events outside any story (up to ``max_events``), so a case
        with no story still has a timeline. The path-view chains are always included.
    """
    stories = []
    for s in analysis.stories[:top]:
        b = story_breakdown(s, analysis.graph)
        stories.append({
            "id": s.story_id,
            "root": s.root_event_id,
            "suspicion": s.suspicion,
            "confidence": s.confidence_score,
            "grade": s.grade.value,
            "rank_score": s.rank_score,
            "techniques": s.techniques,
            "tactics": s.tactics,
            "stages": [x.value for x in s.stages],
            "hosts": s.hosts,
            "omitted_events": s.omitted_events,
            "tampering_flags": s.tampering_flags,
            "confidence_breakdown": b.as_dict(),
            "event_ids": s.event_ids,
            "edges": [{"src": e.src_event_id, "dst": e.dst_event_id, "relation": e.relation,
                       "rule": e.rule_name, "confidence": e.confidence, "dt_s": round(e.time_delta_s, 3)}
                      for e in s.edges],
        })
    ids = story_event_ids(analysis, top)
    if include_all_events:
        seen = set(ids)
        ids += [e.event_id for e in analysis.events if e.event_id not in seen][: max(0, max_events - len(ids))]
    seen_ids = set(ids)
    for c in analysis.chains[:top]:
        for i in c.event_ids:
            if i not in seen_ids:
                seen_ids.add(i)
                ids.append(i)
    return {
        "summary": {
            "events": len(analysis.events),
            "edges": len(analysis.graph.edges),
            "stories": len(analysis.stories),
            "corroborations": analysis.corroborations,
            "indicators": len(analysis.indicators),
            "ledger_records": len(analysis.ledger.records),
            "ledger_ok": analysis.ledger.verify(),
            "timings_s": analysis.timings_s,
            "load_stats": analysis.load_stats,
        },
        "stories": stories,
        "events": [d for i in ids if (d := _event_dict(analysis, i))],
        "chains": [{"id": c.chain_id, "event_ids": c.event_ids, "confidence": c.confidence_score,
                    "grade": c.grade.value, "tampering_flags": c.tampering_flags,
                    "edges": [{"src": e.src_event_id, "dst": e.dst_event_id, "relation": e.relation,
                               "rule": e.rule_name, "confidence": e.confidence, "dt_s": round(e.time_delta_s, 3)}
                              for e in c.edges]} for c in analysis.chains[:top]],
        "indicators": [i.model_dump() for i in analysis.indicators[:500]],
        "artefacts": analysis.artefacts,
    }


def to_json(analysis: Analysis, *, top: int = 20) -> str:
    return json.dumps(to_dict(analysis, top=top), indent=1, default=str)


# --------------------------------------------------------------------- Neo4j
def _cypher_str(v: Any) -> str:
    return json.dumps("" if v is None else str(v))  # JSON string literal == Cypher string literal


def to_cypher(analysis: Analysis, *, top: int = 20) -> str:
    """A self-contained Cypher script (``cypher-shell < out.cypher``)."""
    lines = [
        "// REVENANT provenance graph export",
        "CREATE CONSTRAINT event_id IF NOT EXISTS FOR (e:Event) REQUIRE e.id IS UNIQUE;",
        "CREATE CONSTRAINT story_id IF NOT EXISTS FOR (s:Story) REQUIRE s.id IS UNIQUE;",
    ]
    d = to_dict(analysis, top=top)
    for e in d["events"]:
        props = ", ".join(f"{k}: {_cypher_str(e[k])}" for k in
                          ("time", "type", "actor", "action", "object", "source", "reliability", "hash", "host"))
        lines.append(f"MERGE (e:Event {{id: {_cypher_str(e['id'])}}}) SET e += {{{props}, "
                     f"suspicion: {float(e['suspicion'])}}};")
    for s in d["stories"]:
        lines.append(
            f"MERGE (s:Story {{id: {_cypher_str(s['id'])}}}) SET s.suspicion = {s['suspicion']}, "
            f"s.confidence = {s['confidence']}, s.grade = {_cypher_str(s['grade'])}, "
            f"s.techniques = {json.dumps(s['techniques'])};"
        )
        for eid in s["event_ids"]:
            lines.append(f"MATCH (s:Story {{id: {_cypher_str(s['id'])}}}), (e:Event {{id: {_cypher_str(eid)}}}) "
                         "MERGE (e)-[:IN_STORY]->(s);")
        for ed in s["edges"]:
            lines.append(
                f"MATCH (a:Event {{id: {_cypher_str(ed['src'])}}}), (b:Event {{id: {_cypher_str(ed['dst'])}}}) "
                f"MERGE (a)-[r:CAUSED {{rule: {_cypher_str(ed['rule'])}}}]->(b) "
                f"SET r.relation = {_cypher_str(ed['relation'])}, r.confidence = {ed['confidence']}, "
                f"r.dt_s = {ed['dt_s']};"
            )
    return "\n".join(lines) + "\n"


def push_neo4j(analysis: Analysis, uri: str, user: str, password: str, *, top: int = 20) -> int:
    """Execute the Cypher export against a live Neo4j (optional ``neo4j`` driver)."""
    try:
        from neo4j import GraphDatabase  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("pip install neo4j to push to a live database") from exc
    stmts: Iterable[str] = [s for s in to_cypher(analysis, top=top).splitlines() if s and not s.startswith("//")]
    n = 0
    with GraphDatabase.driver(uri, auth=(user, password)) as drv, drv.session() as sess:  # pragma: no cover
        for st in stmts:
            sess.run(st.rstrip(";"))
            n += 1
    return n  # pragma: no cover
