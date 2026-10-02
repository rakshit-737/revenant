"""Incident-story reconstruction over a real provenance graph.

v0.1 enumerated every simple root-to-leaf path. On a real host that explodes
(explorer.exe alone has thousands of descendants), and a single path is not
how an analyst writes up an incident anyway. v0.2 reconstructs **stories**:

1. Every event gets an ATT&CK-tagged *suspicion* score (`revenant.attack`).
2. Each suspicious event (a *seed*) is walked up its causal ancestry to the
   top-most ancestor that is **not** part of the operating system's own
   process skeleton (services.exe, svchost.exe, explorer.exe, ...). That
   ancestor is the *story root*: typically the attacker's first foothold
   process (a macro-spawned PowerShell, a PsExec service, a WMI child).
3. Seeds that share a root merge into one story, which keeps the root's
   causal subtree (capped, suspicious branches first).
4. Each story is scored for **suspicion** (what it looks like) and
   **confidence** (how well the evidence supports it) separately, then ranked
   by ``rank_score = suspicion * (0.5 + 0.5 * confidence)``.

Keeping suspicion and confidence apart matters in court: "this looks like
credential dumping" and "we are sure these events are causally linked" are
different claims. Every quantity is explainable back to named rules and
heuristics (see docs/adr/0004-stories-not-paths.md).
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass

from .antiforensics import CHAIN_PENALISING
from .attack import TACTICS, EventTags, score_events
from .confidence import ConfidenceBreakdown, score_chain
from .entities import image_key, split_process_ref
from .graph import ProvenanceGraph
from .models import (
    ConfidenceGrade,
    EventType,
    IncidentStory,
    KillChainStage,
    TamperingIndicator,
)

# Processes that form the OS skeleton: a story never climbs above them.
SYSTEM_ROOTS = frozenset(
    {
        "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "svchost.exe", "explorer.exe", "userinit.exe", "taskhostw.exe",
        "taskeng.exe", "sihost.exe", "runtimebroker.", "dllhost.exe", "wmiprvse.exe",
        "searchindexer.", "msiexec.exe", "trustedinstall", "tiworker.exe", "spoolsv.exe",
        "mmc.exe", "conhost.exe", "sppsvc.exe", "wsmprovhost.ex", "gpupdate.exe",
    }
)

# ATT&CK tactic -> Lockheed-Martin kill-chain stage (for the narrative header)
TACTIC_STAGE = {
    "TA0001": KillChainStage.DELIVERY,
    "TA0002": KillChainStage.EXPLOITATION,
    "TA0003": KillChainStage.INSTALLATION,
    "TA0004": KillChainStage.INSTALLATION,
    "TA0005": KillChainStage.EXPLOITATION,
    "TA0006": KillChainStage.ACTIONS,
    "TA0007": KillChainStage.RECON,
    "TA0008": KillChainStage.ACTIONS,
    "TA0009": KillChainStage.ACTIONS,
    "TA0011": KillChainStage.C2,
    "TA0010": KillChainStage.ACTIONS,
    "TA0040": KillChainStage.ACTIONS,
}
_STAGE_ORDER = list(KillChainStage)


@dataclass
class StoryConfig:
    seed_threshold: float = 0.45  # min event suspicion to seed a story
    max_events: int = 200  # cap per story (suspicious branches kept first)
    min_leaf_suspicion: float = 0.2  # benign non-process leaves are omitted
    max_stories: int = 50
    gap_s: float = 1200.0  # silent windows inside a story reported as unknown


def _proc_image(graph: ProvenanceGraph, event_id: str) -> str:
    ev = graph.get_event(event_id)
    if ev is None:
        return ""
    if ev.event_type == EventType.PROCESS_START:
        img = ev.attributes.get("image") or (split_process_ref(ev.object) or ("", ""))[1]
        return image_key(img)
    return ""


def _is_system(graph: ProvenanceGraph, event_id: str) -> bool:
    img = _proc_image(graph, event_id)
    return bool(img) and img in SYSTEM_ROOTS


def _parent(graph: ProvenanceGraph, event_id: str) -> str | None:
    """Strongest causal parent (highest-confidence incoming edge)."""
    edges = graph.in_edges(event_id)
    if not edges:
        return None
    return max(edges, key=lambda e: e.confidence).src_event_id


def story_root(graph: ProvenanceGraph, event_id: str, max_hops: int = 64) -> str:
    """Top-most non-system causal ancestor of ``event_id`` (or itself)."""
    root = event_id
    cur = event_id
    seen = {cur}
    for _ in range(max_hops):
        p = _parent(graph, cur)
        if p is None or p in seen:
            break
        seen.add(p)
        ev = graph.get_event(p)
        if ev is None or _is_system(graph, p) or ev.event_type == EventType.LOGON:
            break
        cur = p
        if ev.event_type == EventType.PROCESS_START:
            root = p
    return root


def _subtree(graph: ProvenanceGraph, root: str, tags: dict[str, EventTags], cap: int) -> list[str]:
    """Root's causal subtree, best-first by suspicion, capped at ``cap``."""
    import heapq

    out: list[str] = [root]
    seen = {root}
    heap: list[tuple[float, str]] = []
    for s in graph.successors(root):
        if s not in seen:
            seen.add(s)
            heapq.heappush(heap, (-_branch_score(graph, s, tags), s))
    while heap and len(out) < cap:
        _, n = heapq.heappop(heap)
        out.append(n)
        for s in graph.successors(n):
            if s not in seen:
                seen.add(s)
                heapq.heappush(heap, (-_branch_score(graph, s, tags), s))
    return out


def _branch_score(graph: ProvenanceGraph, eid: str, tags: dict[str, EventTags]) -> float:
    t = tags.get(eid)
    return t.suspicion if t else 0.0


def _keep(graph: ProvenanceGraph, eid: str, tags: dict[str, EventTags], root: str,
          min_leaf: float, ind_by_event: dict) -> bool:
    """Keep process starts, anything suspicious or tamper-flagged, and the root."""
    if eid == root or eid in ind_by_event:
        return True
    ev = graph.get_event(eid)
    if ev is None:
        return False
    if ev.event_type in (EventType.PROCESS_START, EventType.LOGON):
        return True
    t = tags.get(eid)
    return bool(t) and (t.suspicion >= min_leaf or bool(t.techniques))


def _story_suspicion(ids: list[str], tags: dict[str, EventTags]) -> tuple[float, list[str], list[str]]:
    techniques: dict[str, float] = {}
    tactics: set[str] = set()
    for eid in ids:
        t = tags.get(eid)
        if not t:
            continue
        for tech, tactic, _name in t.techniques:
            techniques[tech] = max(techniques.get(tech, 0.0), t.technique_weight)
            tactics.add(tactic)
    top = sorted((t.suspicion for eid in ids if (t := tags.get(eid))), reverse=True)[:5]
    noisy_or = 1.0
    for s in top:
        noisy_or *= 1.0 - s
    base = 1.0 - noisy_or
    breadth = min(len(tactics), 4) / 4.0  # multi-tactic stories read as intrusions
    suspicion = min(1.0, 0.75 * base + 0.25 * breadth)
    return round(suspicion, 4), sorted(techniques), sorted(tactics)


def _gaps(graph: ProvenanceGraph, ids: list[str], gap_s: float) -> list[str]:
    evs = sorted((e for i in ids if (e := graph.get_event(i))), key=lambda e: e.timestamp)
    out = []
    for a, b in zip(evs, evs[1:]):
        d = (b.timestamp - a.timestamp).total_seconds()
        if d > gap_s:
            out.append(
                f"unknown: no evidence for {int(d)}s between {a.timestamp.isoformat()} "
                f"({a.event_id}) and {b.timestamp.isoformat()} ({b.event_id})"
            )
    return out


def reconstruct_stories(
    graph: ProvenanceGraph,
    indicators: list[TamperingIndicator] | None = None,
    config: StoryConfig | None = None,
    tags: dict[str, EventTags] | None = None,
) -> list[IncidentStory]:
    cfg = config or StoryConfig()
    indicators = indicators or []
    visible = [e for e in graph.events if e.event_id not in graph.shadowed]
    tags = tags if tags is not None else score_events(visible)

    by_root: dict[str, list[str]] = defaultdict(list)
    for e in visible:
        t = tags.get(e.event_id)
        if t and t.suspicion >= cfg.seed_threshold:
            by_root[story_root(graph, e.event_id)].append(e.event_id)

    # indicator index: event id -> indicators touching it
    ind_by_event: dict[str, list[TamperingIndicator]] = defaultdict(list)
    for ind in indicators:
        for eid in ind.event_ids:
            ind_by_event[eid].append(ind)

    stories: list[IncidentStory] = []
    for root, seeds in by_root.items():
        full = _subtree(graph, root, tags, cfg.max_events)
        ids = [i for i in full if _keep(graph, i, tags, root, cfg.min_leaf_suspicion, ind_by_event)]
        omitted = len(full) - len(ids)
        idset = set(ids)
        for s in seeds:  # a seed below the cap must never be dropped
            if s not in idset:
                ids.append(s)
                idset.add(s)
        ids.sort(key=lambda i: (graph.get_event(i).timestamp, i))  # type: ignore[union-attr]
        edges = [e for i in ids for e in graph.out_edges(i) if e.dst_event_id in idset]
        suspicion, techniques, tactics = _story_suspicion(ids, tags)
        stages = sorted({TACTIC_STAGE[t] for t in tactics if t in TACTIC_STAGE}, key=_STAGE_ORDER.index)
        flags: list[str] = []
        seen_ind: set[int] = set()
        for i in ids:
            for ind in ind_by_event.get(i, []):
                if id(ind) in seen_ind:
                    continue
                seen_ind.add(id(ind))
                flags.append(f"{ind.indicator}: {ind.detail}")
        hosts = sorted({h for i in ids if (h := graph.get_event(i).attributes.get("host", ""))})  # type: ignore[union-attr]
        sid = "story-" + hashlib.sha256("|".join(ids).encode()).hexdigest()[:10]
        story = IncidentStory(
            story_id=sid,
            root_event_id=root,
            event_ids=ids,
            edges=edges,
            stages=stages,
            techniques=techniques,
            tactics=tactics,
            hosts=hosts,
            suspicion=suspicion,
            tampering_flags=flags,
            omitted_events=omitted,
        )
        b = story_breakdown(story, graph)
        story.confidence_score = b.score
        story.grade = b.grade
        story.rank_score = round(suspicion * (0.5 + 0.5 * b.score), 4)
        stories.append(story)

    stories.sort(key=lambda s: (-s.rank_score, s.story_id))
    return stories[: cfg.max_stories]


def story_breakdown(story: IncidentStory, graph: ProvenanceGraph) -> ConfidenceBreakdown:
    """Confidence breakdown of a story.

    Only evidence-undermining indicators (timestomp, hash mismatch, clock
    manipulation...) lower confidence. A cleared log is itself a finding -- it
    raises suspicion via T1070 -- but it does not make the surviving events
    less trustworthy, so it is not a confidence penalty.
    """
    penalising = [f for f in story.tampering_flags if f.split(":", 1)[0] in CHAIN_PENALISING]
    return score_chain(story.model_copy(update={"tampering_flags": penalising}), graph)


def story_gaps(graph: ProvenanceGraph, story: IncidentStory, gap_s: float = 1200.0) -> list[str]:
    """Silent windows inside a story, phrased as explicit unknowns."""
    return _gaps(graph, story.event_ids, gap_s)


def tactic_names(tactics: list[str]) -> list[str]:
    return [TACTICS.get(t, t) for t in tactics]


__all__ = [
    "ConfidenceGrade",
    "StoryConfig",
    "SYSTEM_ROOTS",
    "reconstruct_stories",
    "story_breakdown",
    "story_gaps",
    "story_root",
    "tactic_names",
]
