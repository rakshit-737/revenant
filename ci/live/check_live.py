"""Reconstruct a live auditd capture end-to-end and assert on the result.

Run after ``capture_auditd.sh``. Writes ``<out>/live_result.json`` and exits
non-zero if the scripted sequence was not reconstructed. Two kinds of check:

1. **Scenario checks** -- the causal edges the script is known to create
   (spawn, dropped-file-executed, connect, write, delete) and a single story
   that contains the whole sequence.
2. **Kernel ground truth** -- every process-start and effect edge the engine
   inferred is compared with auditd's own ``pid``/``ppid`` fields: the true
   cause of an event is the most recent ``execve`` of that PID before it.
   The engine never reads ``ppid`` directly for effects, and its keys include
   the image name, so this measures the rule engine, not the parser.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from revenant.models import EventType  # noqa: E402
from revenant.pipeline import analyze_paths  # noqa: E402


def truth_edges(events) -> set[tuple[str, str]]:
    last_exec: dict[str, str] = {}
    truth: set[tuple[str, str]] = set()
    for e in sorted(events, key=lambda x: (x.timestamp, int(x.attributes.get("audit_serial", "0")))):
        pid, ppid = e.attributes.get("pid", ""), e.attributes.get("ppid", "")
        if e.event_type == EventType.PROCESS_START:
            if ppid in last_exec:
                truth.add((last_exec[ppid], e.event_id))
            last_exec[pid] = e.event_id
        elif pid in last_exec:
            truth.add((last_exec[pid], e.event_id))
    return truth


def main(out_dir: str) -> int:
    out = Path(out_dir)
    gt = json.loads((out / "ground_truth.json").read_text())
    a = analyze_paths([out / "audit.log"], kind="auditd", host=gt["host"])
    ev = {e.event_id: e for e in a.events}
    edges = {(x.src_event_id, x.dst_event_id): x for x in a.graph.edges}

    def find(pred):
        return [e for e in a.events if pred(e)]

    scen = find(lambda e: e.event_type == EventType.PROCESS_START and gt["scenario"] in e.attributes.get("command_line", ""))
    fetch = find(lambda e: e.event_type == EventType.PROCESS_START and e.attributes.get("image") == gt["dropped_image"])
    drop = find(lambda e: e.event_type == EventType.FILE_WRITE and e.object == f"file:{gt['dropped_image']}")
    conn = find(lambda e: e.event_type == EventType.NETWORK_CONNECT and e.object == f"ip:{gt['peer']}")
    loot = find(lambda e: e.event_type == EventType.FILE_WRITE and e.object == f"file:{gt['fetched_file']}")
    dele = find(lambda e: e.event_type == EventType.FILE_DELETE and e.object == f"file:{gt['fetched_file']}")

    def linked(srcs, dsts, rule_prefix=""):
        return any((s.event_id, d.event_id) in edges and edges[(s.event_id, d.event_id)].rule_name.startswith(rule_prefix)
                   for s in srcs for d in dsts)

    checks = {
        "scenario_start_seen": bool(scen),
        "scenario_spawned_fetcher": linked(scen, fetch),
        "dropped_file_executed": linked(drop, fetch, "dropped_file_executed"),
        "fetcher_connected_to_peer": linked(fetch, conn),
        "fetcher_wrote_file": linked(fetch, loot),
        "delete_attributed": any(d.event_id in {k[1] for k in edges} for d in dele),
    }
    # the story keeps process starts and suspicious leaves; routine writes are
    # summarised as "omitted", so coverage is judged on the scripted processes
    scen_pids = {e.attributes.get("pid") for e in scen}
    children = find(lambda e: e.event_type == EventType.PROCESS_START and e.attributes.get("ppid") in scen_pids)
    seq = {e.event_id for e in scen + children}
    best = None
    for rank, s in enumerate(a.stories, 1):
        cover = len(seq & set(s.event_ids)) / max(len(seq), 1)
        if best is None or cover > best["coverage"]:
            best = {"rank": rank, "story_id": s.story_id, "coverage": round(cover, 3), "events": len(s.event_ids),
                    "grade": s.grade.value, "techniques": s.techniques}
    checks["one_story_covers_sequence"] = bool(best and best["coverage"] >= 0.8)

    truth = truth_edges(a.events)
    proc_edges = {k for k, x in edges.items() if ev.get(k[0]) and ev[k[0]].event_type == EventType.PROCESS_START
                  and x.rule_name != "dropped_file_executed"}
    tp = len(proc_edges & truth)
    p = tp / len(proc_edges) if proc_edges else 0.0
    r = tp / len(truth) if truth else 0.0
    result = {
        "events": len(a.events),
        "event_types": {t.value: sum(e.event_type == t for e in a.events) for t in EventType
                        if any(e.event_type == t for e in a.events)},
        "edges": len(a.graph.edges),
        "stories": len(a.stories),
        "load_stats": a.load_stats,
        "timings_s": a.timings_s,
        "checks": checks,
        "best_story": best,
        "kernel_truth": {"truth_edges": len(truth), "inferred": len(proc_edges), "tp": tp,
                         "precision": round(p, 4), "recall": round(r, 4),
                         "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0},
        "custody_records": len(a.ledger.records),
    }
    (out / "live_result.json").write_text(json.dumps(result, indent=2, default=str))
    print(json.dumps(result, indent=2, default=str))
    ok = all(checks.values()) and p >= 0.9 and r >= 0.9
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "live-out"))
