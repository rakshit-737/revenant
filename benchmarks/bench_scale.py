"""B4 -- throughput and scaling on the APT29 day-1 capture (real events).

1. End-to-end stage timings on the full capture (parse, fusion, rules,
   anti-forensics, stories) and events/second.
2. Rule-engine scaling: the v0.1 engine compared every ordered event pair
   (O(n^2)); v0.2 indexes causes by entity key (O(n log n)). Both are timed
   on growing time-ordered prefixes of the capture and a log-log slope is
   fitted. The v0.1 algorithm is reproduced below verbatim in structure (pair
   loop + per-rule predicate) so the comparison is like-for-like.
"""

from __future__ import annotations

import math
import time

from common import APT29_DIR, environment, load_cached, require, write_json

from revenant.graph import ProvenanceGraph
from revenant.models import EventType
from revenant.pipeline import analyze_events
from revenant.rules import RuleEngine

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


def main() -> int:
    if not require(APT29_DIR, "APT29 day-1 capture"):
        return 0
    t0 = time.perf_counter()
    events, st = load_cached(APT29_DIR, "otrf_apt29_day1-apt29_day1")
    load_s = time.perf_counter() - t0
    events = sorted(events, key=lambda e: (e.timestamp, e.event_id))

    t0 = time.perf_counter()
    a = analyze_events(events, chains=False)
    total = time.perf_counter() - t0
    e2e = {
        "events": len(events),
        "raw_rows": st["rows"],
        "mapping_coverage": st["coverage"],
        "load_s_cached": round(load_s, 2),
        "stage_s": a.timings_s,
        "analysis_s": round(total, 2),
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
    print(e2e["events"], "events in", e2e["analysis_s"], "s;", e2e["stage_s"])

    sizes_old = [500, 1000, 2000, 4000]
    sizes_new = [500, 1000, 2000, 4000, 16000, 64000, len(events)]
    old, new = [], []
    for n in sizes_old:
        t, k = _timed(v01_infer, events[:n])
        old.append({"n": n, "seconds": round(t, 3), "edges": k})
        print("v0.1", n, round(t, 2))
    for n in sizes_new:
        t, k = _timed(v02_infer, events[:n])
        new.append({"n": n, "seconds": round(t, 3), "edges": k})
        print("v0.2", n, round(t, 2))
    s_old = slope([(r["n"], r["seconds"]) for r in old])
    s_new = slope([(r["n"], r["seconds"]) for r in new])
    full_n = len(events)
    extrapolated = old[-1]["seconds"] * (full_n / old[-1]["n"]) ** s_old
    out = {
        "benchmark": "scale_apt29_day1",
        "environment": environment(),
        "end_to_end": e2e,
        "rule_engine_scaling": {
            "v01_pairwise": old, "v02_indexed": new,
            "loglog_slope_v01": s_old, "loglog_slope_v02": s_new,
            "v01_extrapolated_full_capture_s": round(extrapolated, 1),
        },
    }
    print("slopes", s_old, s_new, "v0.1 extrapolated full:", round(extrapolated), "s")
    write_json("scale.json", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
