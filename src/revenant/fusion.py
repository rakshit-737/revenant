"""Cross-artefact fusion: detect the *same* fact reported by several sources.

Examples on real data: Sysmon EID 1 and Security 4688 for the same process;
Sysmon EID 5 and Security 4689 for its exit; a Volatility ``pslist`` entry
for a process the logs also saw; a plaso prefetch execution for an image
Sysmon saw starting.

Matched events are not merged (evidence is never rewritten). One event is
chosen as *primary* (richest source first) and the others are recorded as
its corroborations; the graph marks them *shadowed* so the rule engine
builds one causal node per fact. Corroboration then feeds the confidence
scorer: a chain whose facts are attested by independent artefacts scores
higher (demo scenario 3 in the spec).
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass

from .entities import actor_process_key, event_host, image_key, norm_user, object_process_key, split_process_ref
from .graph import ProvenanceGraph
from .models import Event, EventType

# richer sources first: Sysmon carries GUIDs, hashes and command lines
SOURCE_PRIORITY = ["sysmon", "security", "memory", "system", "powershell", "plaso", "authlog", "auth"]


def _prio(ev: Event) -> tuple[int, float]:
    try:
        p = SOURCE_PRIORITY.index(ev.source_artifact)
    except ValueError:
        p = len(SOURCE_PRIORITY)
    return (p, -ev.source_reliability.weight)


@dataclass
class FusionSpec:
    name: str
    types: frozenset[EventType]
    tolerance_s: float

    def key(self, ev: Event) -> str | None:  # pragma: no cover - overridden
        raise NotImplementedError


class _ProcStart(FusionSpec):
    def key(self, ev: Event) -> str | None:
        return object_process_key(ev)


class _ProcStop(FusionSpec):
    def key(self, ev: Event) -> str | None:
        return actor_process_key(ev)


class _Logon(FusionSpec):
    def key(self, ev: Event) -> str | None:
        u = norm_user(ev.attributes.get("user") or ev.actor.split(":", 1)[-1])
        host = event_host(ev) or ev.object.split(":", 1)[-1].lower()
        ip = ev.attributes.get("src_ip", "")
        return f"{host}|{u}|{ip}" if u else None


class _NetConn(FusionSpec):
    def key(self, ev: Event) -> str | None:
        k = actor_process_key(ev)
        return f"{k}|{ev.object}" if k else None


class _Execution(FusionSpec):
    """plaso execution evidence (no PID) vs a logged process start."""

    def key(self, ev: Event) -> str | None:
        parts = split_process_ref(ev.object)
        if not parts:
            return None
        return f"{event_host(ev)}|{image_key(parts[1])}"


SPECS: list[FusionSpec] = [
    _ProcStart("process_start", frozenset({EventType.PROCESS_START}), 2.0),
    _ProcStop("process_stop", frozenset({EventType.PROCESS_STOP}), 2.0),
    _Logon("logon", frozenset({EventType.LOGON}), 5.0),
    _NetConn("network", frozenset({EventType.NETWORK_CONNECT}), 2.0),
]
EXECUTION_SPEC = _Execution("execution", frozenset({EventType.EXECUTION, EventType.PROCESS_START}), 10.0)


def fuse(graph: ProvenanceGraph) -> int:
    """Record corroborations in ``graph``. Returns the number of links added."""
    events = graph.events
    added = 0
    for spec in SPECS:
        groups: dict[str, list[Event]] = defaultdict(list)
        for e in events:
            if e.event_type in spec.types:
                k = spec.key(e)
                if k:
                    groups[k].append(e)
        for group in groups.values():
            added += _link_group(graph, group, spec.tolerance_s)
    # prefetch/amcache execution evidence vs logged starts (image-level match)
    starts: dict[str, list[Event]] = defaultdict(list)
    execs: list[Event] = []
    for e in events:
        if e.event_type == EventType.PROCESS_START and e.event_id not in graph.shadowed:
            parts = split_process_ref(e.object)
            if parts:
                starts[f"{event_host(e)}|{image_key(parts[1])}"].append(e)
        elif e.event_type == EventType.EXECUTION:
            execs.append(e)
    for x in execs:
        k = EXECUTION_SPEC.key(x)
        cands = starts.get(k or "", [])
        if not cands:
            continue
        ts = [c.timestamp.timestamp() for c in cands]
        i = bisect.bisect_left(ts, x.timestamp.timestamp())
        best = None
        for j in (i - 1, i):
            if 0 <= j < len(cands):
                d = abs(ts[j] - x.timestamp.timestamp())
                if d <= EXECUTION_SPEC.tolerance_s and (best is None or d < best[0]):
                    best = (d, cands[j])
        if best:
            graph.add_corroboration(best[1].event_id, x.event_id)
            added += 1
    return added


def _link_group(graph: ProvenanceGraph, group: list[Event], tol: float) -> int:
    """Within one entity key, cluster events from *different* sources in time."""
    if len({e.source_artifact for e in group}) < 2:
        return 0
    group.sort(key=lambda e: e.timestamp)
    added = 0
    used: set[str] = set()
    for i, e in enumerate(group):
        if e.event_id in used:
            continue
        cluster = [e]
        for f in group[i + 1:]:
            if (f.timestamp - e.timestamp).total_seconds() > tol:
                break
            if f.event_id in used or f.source_artifact in {c.source_artifact for c in cluster}:
                continue
            cluster.append(f)
        if len(cluster) < 2:
            continue
        cluster.sort(key=_prio)
        primary = cluster[0]
        for other in cluster[1:]:
            graph.add_corroboration(primary.event_id, other.event_id)
            used.add(other.event_id)
            added += 1
        used.add(primary.event_id)
    return added
