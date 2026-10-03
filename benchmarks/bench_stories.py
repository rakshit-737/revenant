"""B2 -- incident-story ranking vs flat timelines on labelled OTRF captures.

Every OTRF atomic dataset ships metadata (``_metadata/SDWIN-*.yaml``) naming
the ATT&CK technique(s) the capture simulates. For each labelled capture we
ask: how fast does an analyst reach evidence of the labelled technique?

Methods (all read the same parsed events):

* ``chronological`` -- a plaso/psort-style super-timeline read top to bottom.
* ``flat_suspicion`` -- the same timeline sorted by per-event suspicion
  (identical ATT&CK heuristics, **no graph**): isolates what the graph adds.
* ``revenant`` -- ranked incident stories; stories read in rank order, events
  within a story in time order.

Metrics:

* ``hit@k`` -- reached evidence of a labelled technique (parent-id match,
  e.g. T1003 ~ T1003.001) within an **equal event budget** of *k* x the
  capture's median story size, for every method (REVENANT included: its
  story-ordered event list is cut at the same budget).
* ``story_hit@k`` -- the story-unit view: REVENANT reads its top *k* whole
  stories (whatever their size) and the flat methods get exactly the same
  number of events (the summed size of those *k* stories).

An earlier version compared REVENANT's whole-story hit@k with a k x median
budget for the flat methods, which gave REVENANT more reading budget; both
equal-budget views are reported now, with paired McNemar tests and Wilson CIs.
* ``events_to_evidence`` -- events read before the first tagged event (the
  spec's "analyst time-to-story" proxy). Median and mean over captures.
* ``in_vocabulary`` -- whether the labelled technique appears in REVENANT's
  heuristic list at all; captures outside the vocabulary cannot be hit by any
  method here and are reported separately (honest coverage).

Caveat: "tagged with technique T" uses REVENANT's own heuristics as the
detector for every method. The benchmark therefore measures *ranking and
grouping*, not detector quality, and it is not a substitute for analyst-
written ground truth.
"""

from __future__ import annotations

import statistics
import time

from common import atomic_datasets, environment, load_cached, write_json
from stats import provenance

from revenant.attack import HEURISTICS, technique_parent
from revenant.pipeline import analyze_events

VOCAB = {technique_parent(h.technique) for h in HEURISTICS}


def _hit(tags, eid: str, labels: set[str]) -> bool:
    t = tags.get(eid)
    return bool(t) and any(technique_parent(x[0]) in labels for x in t.techniques)


def _first_hit(order: list[str], tags, labels: set[str]) -> int | None:
    for i, eid in enumerate(order):
        if _hit(tags, eid, labels):
            return i
    return None


def evaluate_one(ds) -> dict | None:
    events, st = load_cached(ds.path, f"otrf_atomic-{ds.name}")
    if not events:
        return None
    t0 = time.perf_counter()
    a = analyze_events(events, chains=False)
    elapsed = time.perf_counter() - t0
    labels = set(ds.techniques)
    tags = a.tags
    visible = [e for e in a.graph.events if e.event_id not in a.graph.shadowed]

    chrono = [e.event_id for e in visible]
    flat = [e.event_id for e in sorted(visible, key=lambda e: (-tags[e.event_id].suspicion, e.timestamp))]
    story_order: list[str] = []
    story_of: dict[str, int] = {}
    for rank, s in enumerate(a.stories):
        for eid in s.event_ids:
            if eid not in story_of:
                story_of[eid] = rank
                story_order.append(eid)

    sizes = [len(s.event_ids) for s in a.stories] or [1]
    med = max(1, int(statistics.median(sizes)))
    first_story = next((r for r, s in enumerate(a.stories)
                        if any(_hit(tags, eid, labels) for eid in s.event_ids)), None)
    out = {
        "dataset": ds.name,
        "labels": sorted(labels),
        "in_vocabulary": bool(labels & VOCAB),
        "events": len(visible),
        "stories": len(a.stories),
        "median_story_size": med,
        "first_hit_story_rank": first_story,
        "analysis_s": round(elapsed, 4),
        "coverage": st["coverage"],
        "unreadable": len(st["unreadable_files"]),
    }
    for name, order in (("chronological", chrono), ("flat_suspicion", flat), ("revenant", story_order)):
        out[f"{name}_events_to_evidence"] = _first_hit(order, tags, labels)
    for k in (1, 3, 5):
        budget = k * med
        story_budget = sum(len(s.event_ids) for s in a.stories[:k])
        out[f"revenant_story_hit@{k}"] = first_story is not None and first_story < k
        out[f"story_budget@{k}"] = story_budget
        for name in ("chronological", "flat_suspicion", "revenant"):
            f = out[f"{name}_events_to_evidence"]
            out[f"{name}_hit@{k}"] = f is not None and f < budget
            if name != "revenant":
                out[f"{name}_story_hit@{k}"] = f is not None and f < story_budget
    return out


def summarise(rows: list[dict]) -> dict:
    from stats import mcnemar_exact, wilson

    s: dict = {"captures": len(rows)}
    for m in ("chronological", "flat_suspicion", "revenant"):
        found = [r[f"{m}_events_to_evidence"] for r in rows if r[f"{m}_events_to_evidence"] is not None]
        s[m] = {
            "found": len(found),
            "median_events_to_evidence": statistics.median(found) if found else None,
            "mean_events_to_evidence": round(statistics.mean(found), 1) if found else None,
            **{f"hit@{k}": round(sum(r[f"{m}_hit@{k}"] for r in rows) / len(rows), 4) if rows else 0.0
               for k in (1, 3, 5)},
            **{f"hit@{k}_ci95": wilson(sum(r[f"{m}_hit@{k}"] for r in rows), len(rows)) for k in (1, 3, 5)},
            **{f"story_hit@{k}": round(sum(r[f"{m}_story_hit@{k}"] for r in rows) / len(rows), 4) if rows else 0.0
               for k in (1, 3, 5)},
            **{f"story_hit@{k}_ci95": wilson(sum(r[f"{m}_story_hit@{k}"] for r in rows), len(rows))
               for k in (1, 3, 5)},
        }
    tests = {}
    for view in ("hit", "story_hit"):
        for k in (1, 3, 5):
            b = sum(r[f"revenant_{view}@{k}"] and not r[f"flat_suspicion_{view}@{k}"] for r in rows)
            c = sum(r[f"flat_suspicion_{view}@{k}"] and not r[f"revenant_{view}@{k}"] for r in rows)
            tests[f"{view}@{k}"] = {"revenant_only": b, "flat_only": c, "mcnemar_p": mcnemar_exact(b, c)}
    s["revenant_vs_flat_suspicion"] = tests
    return s


def main() -> int:
    rows = []
    for ds in atomic_datasets(labelled_only=True):
        r = evaluate_one(ds)
        if r is not None:
            rows.append(r)
            print(f"{ds.name[:55]:55s} {r['labels']} story#{r['first_hit_story_rank']} "
                  f"chrono={r['chronological_events_to_evidence']} flat={r['flat_suspicion_events_to_evidence']} "
                  f"rev={r['revenant_events_to_evidence']}")
    in_vocab = [r for r in rows if r["in_vocabulary"]]
    out = {
        "benchmark": "story_ranking_vs_flat_timeline",
        "environment": environment(),
        "all": summarise(rows),
        "in_vocabulary": summarise(in_vocab),
        "rows": rows,
        "source": provenance("bench-extended"),
    }
    print("ALL", out["all"])
    print("IN-VOCAB", out["in_vocabulary"])
    write_json("stories.json", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
