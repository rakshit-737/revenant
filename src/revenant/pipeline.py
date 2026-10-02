"""End-to-end orchestration.

Two entry points share one engine:

* `run` -- legacy v0.1 API over raw ``(kind, record)`` tuples (synthetic
  scenarios, hand-written fixtures).
* `analyze_paths` / `analyze_events` -- real artefacts (OTRF JSON,
  ``.evtx``, plaso, Volatility, auth.log) loaded by `revenant.parsers`.

Stages: ingest + integrity hashing -> custody ledger -> provenance graph ->
cross-artefact fusion (corroboration) -> causal rules -> anti-forensics scan
-> incident stories (ATT&CK-tagged, suspicion + confidence) and, for small
graphs, v0.1 path chains. The custody ledger records every stage so every
derived claim is traceable to the ingest records it depends on.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .antiforensics import annotate_chain, scan
from .attack import EventTags, score_events
from .confidence import apply_score
from .fsutil import iter_files
from .fusion import fuse
from .graph import ProvenanceGraph
from .integrity import CustodyLedger
from .models import Event, IncidentStory, ProvenanceChain, TamperingIndicator
from .normalize import normalize_batch
from .reconstruct import ChainReconstructor
from .rules import RuleEngine
from .stories import StoryConfig, reconstruct_stories

# path enumeration is exponential in fan-out; only run it on small graphs
MAX_EVENTS_FOR_CHAINS = 2_000
_ARTEFACT_SUFFIXES = (".json", ".jsonl", ".evtx", ".csv", ".log")
_LOADER_OPTS = ("year", "utc_offset_hours", "host")


@dataclass
class Analysis:
    events: list[Event]
    graph: ProvenanceGraph
    chains: list[ProvenanceChain]
    indicators: list[TamperingIndicator]
    ledger: CustodyLedger = field(default_factory=CustodyLedger)
    stories: list[IncidentStory] = field(default_factory=list)
    tags: dict[str, EventTags] = field(default_factory=dict)
    corroborations: int = 0
    load_stats: dict[str, Any] = field(default_factory=dict)
    timings_s: dict[str, float] = field(default_factory=dict)
    artefacts: list[dict[str, str]] = field(default_factory=list)


def _digest(items: Iterable[str]) -> str:
    h = hashlib.sha256()
    for i in items:
        h.update(i.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def analyze_events(
    events: list[Event],
    *,
    backend: str = "auto",
    use_guids: bool = True,
    story_config: StoryConfig | None = None,
    ledger: CustodyLedger | None = None,
    chains: bool | None = None,
) -> Analysis:
    """Run the full engine over already-normalized, hashed events."""
    t: dict[str, float] = {}
    ledger = ledger or CustodyLedger()
    t0 = time.perf_counter()
    events = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    for ev in events:
        ledger.record_ingest(ev)
    t["ingest"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    graph = ProvenanceGraph(backend=backend)
    graph.add_events(events)
    corroborations = fuse(graph)
    t["fusion"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    RuleEngine(use_guids=use_guids).infer(graph)
    t["rules"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    indicators = scan(graph)
    t["antiforensics"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    visible = [e for e in graph.events if e.event_id not in graph.shadowed]
    tags = score_events(visible)
    stories = reconstruct_stories(graph, indicators, story_config, tags=tags)
    t["stories"] = time.perf_counter() - t0

    out_chains: list[ProvenanceChain] = []
    if chains or (chains is None and len(events) <= MAX_EVENTS_FOR_CHAINS):
        t0 = time.perf_counter()
        out_chains = ChainReconstructor(graph).reconstruct()
        for chain in out_chains:
            annotate_chain(chain, indicators)
            apply_score(chain, graph)  # re-score now that tampering flags are set
        out_chains.sort(key=lambda c: c.confidence_score, reverse=True)
        t["chains"] = time.perf_counter() - t0

    ledger.append("reconstruct", digest=_digest(e.src_event_id + ">" + e.dst_event_id for e in graph.edges),
                  artifact=f"{len(graph.edges)} edges")
    ledger.append("reconstruct", digest=_digest(s.story_id for s in stories), artifact=f"{len(stories)} stories")
    return Analysis(
        events=events,
        graph=graph,
        chains=out_chains,
        indicators=indicators,
        ledger=ledger,
        stories=stories,
        tags=tags,
        corroborations=corroborations,
        timings_s={k: round(v, 4) for k, v in t.items()},
    )


def analyze_paths(
    paths: list[str | Path],
    *,
    kind: str | None = None,
    include_noisy: bool = False,
    **kwargs: Any,
) -> Analysis:
    """Load artefacts from disk (auto-detecting their kind) and analyse them.

    Loader options (``year`` and ``utc_offset_hours`` for auth.log, ``host``
    for Volatility output) are routed to the parsers; everything else goes to
    `analyze_events`.
    """
    from .parsers import LoadStats, load_path

    loader_opts = {k: kwargs.pop(k) for k in _LOADER_OPTS if k in kwargs}

    ledger = CustodyLedger()
    events: list[Event] = []
    stats = LoadStats()
    artefacts: list[dict[str, str]] = []
    t0 = time.perf_counter()
    for p in paths:
        p = Path(p)
        skipped: list[str] = []
        files = [p] if p.is_file() else list(iter_files(p, _ARTEFACT_SUFFIXES, skipped))
        for s in skipped:  # links inside evidence are never followed; record that they existed
            ledger.append("skipped_link", digest="0" * 64, artifact=Path(s).name)
        for f in files:  # hash the raw artefact before parsing: evidence integrity
            try:
                digest = file_sha256(f)
            except OSError:  # unreadable (e.g. AV-quarantined): logged, not hashed
                ledger.append("acquire_failed", digest="0" * 64, artifact=f.name)
                continue
            ledger.append("acquire", digest=digest, artifact=f.name)
            artefacts.append({"path": str(f), "sha256": digest})
        events.extend(load_path(p, kind, stats=stats, include_noisy=include_noisy, **loader_opts))
    parse_s = time.perf_counter() - t0
    analysis = analyze_events(events, ledger=ledger, **kwargs)
    analysis.load_stats = stats.as_dict()
    analysis.timings_s = {"parse": round(parse_s, 4), **analysis.timings_s}
    analysis.artefacts = artefacts
    return analysis


def run(records: list[tuple[str, dict[str, Any]]], *, backend: str = "auto") -> Analysis:
    """v0.1 API: normalize raw ``(kind, record)`` pairs and analyse them."""
    return analyze_events(normalize_batch(records), backend=backend, chains=True)
