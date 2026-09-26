"""B3 -- anti-forensics detection + binary EVTX parsing on EVTX-ATTACK-SAMPLES.

EVTX-ATTACK-SAMPLES (sbousseaden, GPL-3.0) is ~280 raw ``.evtx`` files, each
recording one attack technique. File names describe what was done, so a
file-level label is available without looking at REVENANT's output:

* **positive** -- the file records log/timestamp tampering. Defined *before*
  running, by the keyword regex ``POSITIVE`` below (timestomp, log cleared,
  event-log service crash/tamper, logging disabled, anti-forensics).
* **negative** -- every other technique file.

Methods (file flagged if the detector fires on any event):

* ``baseline_1102_104`` -- the ubiquitous SIEM query: Security 1102 or
  System 104 present.
* ``revenant`` -- every REVENANT tamper indicator except ``log_gap`` (a
  coverage note, not an accusation).

Caveat: many sample files were recorded right after the author cleared the
logs, so a 1102 in a "negative" file is often a *true* event with an
imperfect file label. Both methods suffer equally; per-indicator counts are
reported so the reader can judge.

Also reports EVTX parser throughput and event-type coverage.
"""

from __future__ import annotations

import re
import time
from collections import Counter

from common import EVTX_SAMPLES, environment, require, write_json

from revenant.antiforensics import scan
from revenant.graph import ProvenanceGraph
from revenant.models import EventType
from revenant.parsers.evtx import load_evtx
from revenant.parsers.otrf import LoadStats
from revenant.parsers.windows import channel_kind

POSITIVE = re.compile(r"timestomp|log_cleared|eventlog|logging_disabled|scriptblocklogging|antiforensics",
                      re.IGNORECASE)
EXCLUDED = {"log_gap"}


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0}


def _count(rows) -> dict:
    total: Counter = Counter()
    for r in rows:
        total.update(r["indicators"])
    return dict(total)


def main() -> int:
    if not require(EVTX_SAMPLES, "EVTX-ATTACK-SAMPLES"):
        return 0
    files = sorted(EVTX_SAMPLES.rglob("*.evtx"))
    rows = []
    total = LoadStats()
    t_parse = 0.0
    n_events = 0
    types = Counter()
    for f in files:
        st = LoadStats()
        t0 = time.perf_counter()
        events = load_evtx(f, stats=st)
        t_parse += time.perf_counter() - t0
        total.rows += st.rows
        total.mapped += st.mapped
        total.bad_rows += st.bad_rows
        total.unmapped.update(st.unmapped)
        total.unreadable_files += st.unreadable_files
        n_events += len(events)
        types.update(e.event_type.value for e in events)
        g = ProvenanceGraph(backend="memory")
        g.add_events(events)
        inds = [i for i in scan(g) if i.indicator not in EXCLUDED]
        kinds = Counter(i.indicator for i in inds)
        rows.append({
            "file": f.name,
            "tactic_dir": f.parent.name,
            "positive": bool(POSITIVE.search(f.name)),
            "unreadable": bool(st.unreadable_files),
            "events": len(events),
            "baseline_1102_104": any(e.event_type == EventType.LOG_CLEARED for e in events),
            "revenant": bool(inds),
            "revenant_high_only": any(i.severity == "high" for i in inds),
            "indicators": dict(kinds),
        })
    readable = [r for r in rows if not r["unreadable"]]
    supported = total.mapped + sum(n for k, n in total.unmapped.items()
                                   if channel_kind({"Channel": k.rsplit(":", 1)[0]}) is not None)
    out = {
        "benchmark": "antiforensics_evtx_attack_samples",
        "environment": environment(),
        "files": len(files),
        "readable_files": len(readable),
        "positives": sum(r["positive"] for r in readable),
        "parser": {
            "records": total.rows,
            "mapped": total.mapped,
            "bad_records": total.bad_rows,
            "coverage": round(total.mapped / total.rows, 4) if total.rows else 0.0,
            # records in channels REVENANT interprets (Sysmon, Security, System, PowerShell);
            # the rest are ETW traces / application logs outside the mapper's scope
            "supported_channel_records": supported,
            "coverage_supported_channels": round(total.mapped / supported, 4) if supported else 0.0,
            "records_per_s": round(total.rows / t_parse, 1) if t_parse else None,
            "event_types": dict(types.most_common()),
            "top_unmapped": total.unmapped.most_common(10),
            "unreadable_files": len(total.unreadable_files),
        },
        "methods": {},
        "indicator_counts_positive_files": _count(r for r in readable if r["positive"]),
        "indicator_counts_negative_files": _count(r for r in readable if not r["positive"]),
        "rows": rows,
    }
    for m in ("baseline_1102_104", "revenant", "revenant_high_only"):
        tp = sum(r[m] and r["positive"] for r in readable)
        fp = sum(r[m] and not r["positive"] for r in readable)
        fn = sum((not r[m]) and r["positive"] for r in readable)
        out["methods"][m] = prf(tp, fp, fn)
    out["missed_positives"] = [r["file"] for r in readable if r["positive"] and not r["revenant"]]
    print(out["parser"])
    print(out["methods"])
    print("missed:", out["missed_positives"])
    print("pos:", out["indicator_counts_positive_files"], "neg:", out["indicator_counts_negative_files"])
    write_json("antiforensics.json", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
