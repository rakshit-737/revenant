"""B4 -- throughput and scaling on the APT29 day-1 capture (real events).

1. End-to-end stage timings on the full capture (parse, fusion, rules,
   anti-forensics, stories) and events/second.
2. Rule-engine scaling: the v0.1 engine compared every ordered event pair
   (O(n^2)); v0.2 indexes causes by entity key (O(n log n)). Both are timed
   on growing time-ordered prefixes of the capture and a log-log slope is
   fitted. The v0.1 algorithm is reproduced below verbatim in structure (pair
   loop + per-rule predicate) so the comparison is like-for-like.

Timings are repeated (end to end ``REPS_E2E`` times, each scaling point
``REPS_POINT`` times) and reported as median and interquartile range; both
slopes are also fitted on the common range (500-4,000 events) so they compare
like with like. Runs on a GitHub-hosted runner (``bench-extended``, part
``scale``) so the numbers come from a stated, reproducible machine.
"""

from __future__ import annotations

import math
import statistics
import time

from common import APT29_DIR, environment, load_cached, require, write_json
from stats import percentile, provenance

from revenant.graph import ProvenanceGraph
from revenant.models import EventType
from revenant.pipeline import analyze_events
from revenant.rules import RuleEngine

REPS_E2E = 5
REPS_POINT = 3
COMMON_MAX = 4000

# ----------------------------------------------------- v0.1 engine (baseline)
_V01 = [  # (relation, window_s, predicate)
    ("spawned", 3600, lambda s, d: s.event_type == EventType.PROCESS_START
     and d.event_type == EventType.PROCESS_START and s.object == d.actor),
    ("wrote", 1800, lambda s, d: s.event_type == EventType.PROCESS_START
     and d.event_type == EventType.FILE_WRITE and s.object == d.actor),
    ("connected", 1800, lambda s, d: s.event_type == EventType.PROCESS_START
     and d.event_type == EventType.NETWORK_CONNECT and s.object == d.actor),
    ("persisted", 1800, lambda s, d: s.event_type == EventType.PROCESS_START
     and d.event_type == EventType.REGISTRY_SET and s.object == d.actor),
    ("resolved", 1800, lambda s, d: s.event_type == EventType.PROCESS_START
     and d.event_type == EventType.DNS_QUERY and s.object == d.actor),
    ("session_of", 7200, lambda s, d: s.event_type == EventType.LOGON
     and d.event_type == EventType.PROCESS_START and bool(s.attributes.get("user"))
     and d.attributes.get("user") == s.attributes.get("user")),
]


def v01_infer(events) -> int:
    n = 0
    for i, src in enumerate(events):
        for dst in events[i + 1:]:
            delta = (dst.timestamp - src.timestamp).total_seconds()
            if delta < 0:
                continue
            for _rel, window, pred in _V01:
                if delta <= window and pred(src, dst):
                    n += 1
    return n


def v02_infer(events) -> int:
    g = ProvenanceGraph(backend="memory")
    g.add_events(events)
    return len(RuleEngine(use_guids=False).infer(g))


def _timed(fn, *a):
    t0 = time.perf_counter()
    r = fn(*a)
    return time.perf_counter() - t0, r


def slope(points: list[tuple[int, float]]) -> float:
    xs = [math.log(n) for n, _ in points]
    ys = [math.log(max(t, 1e-6)) for _, t in points]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    return round(sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs), 3)


def _summary(xs: list[float]) -> dict:
    return {"median": round(statistics.median(xs), 3), "q1": round(percentile(xs, 0.25), 3),
            "q3": round(percentile(xs, 0.75), 3), "runs": [round(x, 3) for x in xs]}


def main() -> int:
    if not require(APT29_DIR, "APT29 day-1 capture"):
        return 0
    t0 = time.perf_counter()
    events, st = load_cached(APT29_DIR, "otrf_apt29_day1-apt29_day1")
    load_s = time.perf_counter() - t0
    events = sorted(events, key=lambda e: (e.timestamp, e.event_id))

    totals, stages, a = [], [], None
    for _ in range(REPS_E2E):
        t0 = time.perf_counter()
        a = analyze_events(events, chains=False)
        totals.append(time.perf_counter() - t0)
        stages.append(a.timings_s)
    assert a is not None
    total = statistics.median(totals)
    e2e = {
        "events": len(events),
        "raw_rows": st["rows"],
        "mapping_coverage": st["coverage"],
        "load_s_cached": round(load_s, 2),
        "repetitions": REPS_E2E,
        "analysis_s": _summary(totals),
        "stage_s": {k: round(statistics.median(x[k] for x in stages), 3) for k in stages[0]},
        "events_per_s": round(len(events) / total, 1),
        "edges": len(a.graph.edges),
        "corroborations": a.corroborations,
        "stories": len(a.stories),
        "indicators": len(a.indicators),
        "hosts_in_top10_stories": sorted({h for s in a.stories[:10] for h in s.hosts}),
        "top_stories": [{"techniques": s.techniques, "suspicion": s.suspicion, "confidence": s.confidence_score,
                         "grade": s.grade.value, "events": len(s.event_ids), "hosts": s.hosts}
                        for s in a.stories[:10]],
    }
    print(e2e["events"], "events, median", e2e["analysis_s"], "s;", e2e["stage_s"])

    sizes_old = [500, 1000, 2000, COMMON_MAX]
    sizes_new = [500, 1000, 2000, COMMON_MAX, 16000, 64000, len(events)]
    old, new = [], []
    for sizes, fn, rows, label in ((sizes_old, v01_infer, old, "v0.1"), (sizes_new, v02_infer, new, "v0.2")):
        for n in sizes:
            runs = [_timed(fn, events[:n]) for _ in range(REPS_POINT)]
            ts = [t for t, _ in runs]
            rows.append({"n": n, "seconds": round(statistics.median(ts), 3), "runs": [round(t, 3) for t in ts],
                         "edges": runs[0][1]})
            print(label, n, rows[-1]["runs"])
    s_old = slope([(r["n"], r["seconds"]) for r in old])
    s_new_common = slope([(r["n"], r["seconds"]) for r in new if r["n"] <= COMMON_MAX])
    s_new = slope([(r["n"], r["seconds"]) for r in new])
    full_n = len(events)
    extrapolated = old[-1]["seconds"] * (full_n / old[-1]["n"]) ** s_old
    out = {
        "benchmark": "scale_apt29_day1",
        "environment": environment(),
        "end_to_end": e2e,
        "rule_engine_scaling": {
            "v01_pairwise": old, "v02_indexed": new, "repetitions_per_point": REPS_POINT,
            "loglog_slope_v01": s_old, "loglog_slope_v02_common_range": s_new_common,
            "loglog_slope_v02": s_new, "common_range": [500, COMMON_MAX],
            "v01_extrapolated_full_capture_s": round(extrapolated, 1),
        },
        "source": provenance("bench-extended"),
    }
    print("slopes v0.1", s_old, "v0.2 common", s_new_common, "v0.2 full", s_new, "v0.1 extrapolated", round(extrapolated))
    write_json("scale.json", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
