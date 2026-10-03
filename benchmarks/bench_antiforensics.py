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
* ``sigma_equivalent`` -- what standard Sigma/Hayabusa rules read: 1102/104,
  Sysmon EID 2 (file creation time changed), registry edits that disable
  logging (EventLog start/file/retention, MiniNt, command-line and PowerShell
  logging keys) and Security 4719 (audit policy changed).
* ``revenant`` -- every REVENANT tamper indicator except ``log_gap`` (a
  coverage note, not an accusation).
* ``revenant_excl_log_cleared`` -- every indicator except ``log_cleared``.
* ``revenant_logging_tamper`` -- only ``audit_tamper`` and ``logging_stopped``,
  the indicators aimed at disabling logging (T1562.002) itself.
* ``revenant_v1_1`` -- the same as ``revenant`` without ``logging_stopped`` (Event Log
  service stop/crash/restart, Security 1100), i.e. REVENANT before this
  release; the new indicator was written *after* seeing B3's misses, so the
  before/after difference on B3 is not a held-out estimate (B3b is).

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
from stats import mcnemar_exact, provenance, wilson

from revenant.antiforensics import _TAMPER_REG, scan
from revenant.graph import ProvenanceGraph
from revenant.models import EventType
from revenant.parsers.evtx import load_evtx
from revenant.parsers.otrf import LoadStats
from revenant.parsers.windows import channel_kind

POSITIVE = re.compile(r"timestomp|log_cleared|eventlog|logging_disabled|scriptblocklogging|antiforensics",
                      re.IGNORECASE)
EXCLUDED = {"log_gap"}
ADDED_AFTER_V1_1 = {"logging_stopped"}
METHODS = ("baseline_1102_104", "sigma_equivalent", "revenant_v1_1", "revenant", "revenant_high_only",
           "revenant_excl_log_cleared", "revenant_logging_tamper")
LOGGING_TAMPER = {"audit_tamper", "logging_stopped"}  # the indicators aimed at T1562.002 itself


def sigma_equivalent(events) -> bool:
    """1102/104, Sysmon EID 2, logging-disable registry edits or 4719: the standard rule set's view."""
    for e in events:
        if e.event_type in (EventType.LOG_CLEARED, EventType.FILE_TIME_CHANGE, EventType.AUDIT_POLICY_CHANGE):
            return True
        if e.event_type == EventType.REGISTRY_SET and _TAMPER_REG.search(e.object):
            return True
    return False


def detections(events, graph) -> dict:
    """Per-method verdicts plus REVENANT's indicator counts for one artefact."""
    inds = [i for i in scan(graph) if i.indicator not in EXCLUDED]
    return {
        "baseline_1102_104": any(e.event_type == EventType.LOG_CLEARED for e in events),
        "sigma_equivalent": sigma_equivalent(events),
        "revenant_v1_1": any(i.indicator not in ADDED_AFTER_V1_1 for i in inds),
        "revenant": bool(inds),
        "revenant_high_only": any(i.severity == "high" for i in inds),
        # a 1102/104 in a capture can be the author clearing logs *before* recording
        "revenant_excl_log_cleared": any(i.indicator != "log_cleared" for i in inds),
        "revenant_logging_tamper": any(i.indicator in LOGGING_TAMPER for i in inds),
        "indicators": dict(Counter(i.indicator for i in inds)),
    }


def score_methods(rows: list[dict], key: str = "positive") -> dict:
    """P/R/F1 with Wilson CIs per method, and exact McNemar tests of REVENANT against the others."""
    out: dict = {}
    for m in METHODS:
        tp = sum(r[m] and r[key] for r in rows)
        fp = sum(r[m] and not r[key] for r in rows)
        fn = sum((not r[m]) and r[key] for r in rows)
        out[m] = {**prf(tp, fp, fn), "precision_wilson95": wilson(tp, tp + fp), "recall_wilson95": wilson(tp, tp + fn)}
    tests: dict = {}
    for other in ("baseline_1102_104", "sigma_equivalent", "revenant_v1_1"):
        for scope, sel in (("positives", [r for r in rows if r[key]]), ("negatives", [r for r in rows if not r[key]]),
                           ("all", rows)):
            b = sum(r["revenant"] and not r[other] for r in sel)
            c = sum(r[other] and not r["revenant"] for r in sel)
            tests[f"revenant_vs_{other}_{scope}"] = {"revenant_only": b, "other_only": c, "mcnemar_p": mcnemar_exact(b, c)}
    return {"methods": out, "paired_tests": tests}


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
        det = detections(events, g)
        rows.append({
            "file": f.name,
            "tactic_dir": f.parent.name,
            "positive": bool(POSITIVE.search(f.name)),
            "unreadable": bool(st.unreadable_files),
            "events": len(events),
            **det,
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
        **score_methods(readable),
        "indicator_counts_positive_files": _count(r for r in readable if r["positive"]),
        "indicator_counts_negative_files": _count(r for r in readable if not r["positive"]),
        "rows": rows,
    }
    out["missed_positives"] = [r["file"] for r in readable if r["positive"] and not r["revenant"]]
    out["source"] = provenance("bench-extended")
    print(out["parser"])
    print(out["methods"])
    print("missed:", out["missed_positives"])
    print("pos:", out["indicator_counts_positive_files"], "neg:", out["indicator_counts_negative_files"])
    write_json("antiforensics.json", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
