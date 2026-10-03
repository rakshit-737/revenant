"""B3b -- anti-forensics on OTRF atomic captures labelled T1562.002 by the dataset authors.

B3 (EVTX-ATTACK-SAMPLES) has only 10 positives, labelled by file name. OTRF's
own ATT&CK metadata (``_metadata/SDWIN-*.yaml``) gives a second, independent
label source: six metadata entries map to T1562.002 (Impair Defenses: Disable
Windows Event Logging) and link 17 host captures:

=====================  =======================================================
SDWIN-220630130349     audit policy modification (auditpol)
SDWIN-220703123711     process command-line logging disabled (2 captures)
SDWIN-220705170038     Security log file path modified (wevtutil)
SDWIN-220708104215     Event Log service start-up type changed (3)
SDWIN-220708104300     Event Log service stopped after its dependents (4)
SDWIN-220803205800     MiniNt registry key created (6)
=====================  =======================================================

No OTRF atomic metadata maps to T1070, so these are the public tamper labels
available. **Positives**: the 17 captures (also reported per metadata entry:
an entry is found when any of its captures is flagged). **Negatives**: every
labelled atomic capture whose metadata maps to neither T1562 nor T1070.

Detectors are those of B3 (``bench_antiforensics.detections``), scored at
capture level with Wilson intervals and exact McNemar tests. Indicator kinds
are counted separately for positives and negatives because many OTRF captures
contain a genuine 1102/104 from the author clearing logs before recording.

Caveat: these captures were part of the B1/B2 corpus while REVENANT was being
developed, so this is not a blind test of the older indicators; the
``logging_stopped`` indicator was written before B3b was run.
"""

from __future__ import annotations

from collections import Counter

from bench_antiforensics import METHODS, detections, score_methods
from common import OTRF_ATOMIC, atomic_datasets, environment, load_cached, require, write_json
from stats import provenance, wilson

from revenant.graph import ProvenanceGraph

LABEL = "T1562.002"


def main() -> int:
    if not require(OTRF_ATOMIC / "_metadata", "OTRF atomic metadata"):
        return 0
    ds = atomic_datasets(labelled_only=True)
    rows = []
    for d in ds:
        positive = LABEL in d.sub_techniques
        if not positive and any(t.startswith(("T1562", "T1070")) for t in d.techniques):
            continue  # other defence-impairment / indicator-removal labels: neither positive nor negative
        events, st = load_cached(d.path, f"otrf_atomic-{d.name}")
        g = ProvenanceGraph(backend="memory")
        g.add_events(events)
        rows.append({"capture": d.name, "metadata_id": d.metadata_id, "title": d.title, "positive": positive,
                     "events": len(events), "unreadable": bool(st.get("unreadable_files")),
                     **detections(events, g)})
    readable = [r for r in rows if not r["unreadable"] and r["events"]]
    pos = [r for r in readable if r["positive"]]
    entries: dict[str, list[dict]] = {}
    for r in pos:
        entries.setdefault(r["metadata_id"], []).append(r)
    entry_level = {}
    for m in METHODS:
        found = sum(any(r[m] for r in v) for v in entries.values())
        entry_level[m] = {"found": found, "entries": len(entries), "recall": round(found / len(entries), 4)
                          if entries else 0.0, "recall_wilson95": wilson(found, len(entries))}
    neg_counts: Counter = Counter()
    pos_counts: Counter = Counter()
    for r in readable:
        (pos_counts if r["positive"] else neg_counts).update(r["indicators"])
    out = {
        "benchmark": "antiforensics_otrf_t1562_002",
        "environment": environment(),
        "label": LABEL,
        "captures": len(rows),
        "readable_captures": len(readable),
        "positives": len(pos),
        "negatives": len(readable) - len(pos),
        "unreadable_or_empty": sorted(r["capture"] for r in rows if r not in readable),
        **score_methods(readable),
        "entry_level": entry_level,
        "entries": {k: [r["capture"] for r in v] for k, v in sorted(entries.items())},
        "indicator_counts_positive_captures": dict(pos_counts),
        "indicator_counts_negative_captures": dict(neg_counts),
        "missed_positives": [r["capture"] for r in pos if not r["revenant"]],
        "rows": rows,
        "source": provenance("bench-extended"),
    }
    print({m: (v["tp"], v["fp"], v["fn"], v["precision"], v["recall"]) for m, v in out["methods"].items()})
    print("entry level:", {m: v["found"] for m, v in entry_level.items()}, "of", len(entries))
    print("missed:", out["missed_positives"])
    write_json("antiforensics_b3b.json", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
