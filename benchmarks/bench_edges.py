"""B1 -- causal-edge accuracy against Sysmon process-GUID ground truth.

Sysmon stamps every event with ``ProcessGuid`` (and ``ParentProcessGuid`` on
EID 1). GUIDs are unique per process instance, so they give an *objective*
answer to "which process-start caused this event?" -- the exact question the
causal rule engine must answer on sources without GUIDs (Security 4688,
plaso, memory). We hide the GUIDs from the engine (``use_guids=False``),
infer edges from host/PID/image/time alone, and score them against the GUID
truth.

Methods compared (same events, same evaluation set):

* ``v01_exact_ref_join`` -- REVENANT v0.1: link to *every* earlier process-start
  whose ``process:pid:image`` string equals the effect's actor, within 1 h.
* ``pid_nearest``        -- flat-timeline analyst heuristic: nearest earlier
  process-start with the same host+PID, within 24 h.
* ``pid_image_nearest``  -- the stronger analyst heuristic: PID-nearest, and
  when the effect has no PID, the nearest earlier start of the same image on
  the same host within 1 h (REVENANT's fallback idea without its keys, PID-reuse
  guard or fusion). Run on the fused input only.
* ``revenant``           -- v0.2 engine: host|PID|image key, nearest cause,
  PID-reuse guard via process-termination events, 24 h window.

The ``*_fused`` variants run the same baselines on the fused, shadow-free event
list REVENANT itself sees (the Security 4688 twin of a Sysmon 1 start is
removed), so the comparison is not inflated by duplicate-record links. The
``v01`` join is a *reconstruction* of v0.1's idea (one 1 h window for all effect
types), not the v0.1 engine itself.

Ablations (REVENANT with one component removed) isolate where the gain comes
from: image in the key, the PID-reuse (termination) guard, the image-only
fallback rules and Sysmon/4688 fusion. Per-capture counts are stored so
capture-clustered bootstrap CIs can be computed (``benchmarks/stats.py``).

Also reports edge-confidence calibration (ECE, Brier, reliability bins), the
held-out ECE of the per-rule table REVENANT ships (``--write-calibration``
refits it in the same run and records its SHA-256), and per-capture
calibration counts so ECE, AUROC and selective-prediction curves can be
bootstrapped over captures (``make_figures.py``).
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

from common import APT29_DIR, atomic_datasets, compound_corpora, environment, load_cached, write_json
from stats import provenance

from revenant.entities import actor_process_key, event_host, object_process_key
from revenant.fusion import fuse
from revenant.graph import ProvenanceGraph
from revenant.models import Event, EventType
from revenant.rules import (
    MAX_CALIBRATED,
    PROCESS_ACTIONS,
    RuleEngine,
    _pid_only_actor,
    _pid_only_object,
    default_rules,
    load_calibration,
)

EFFECT_TYPES = {EventType.PROCESS_START}
for _rel, _types, _c in PROCESS_ACTIONS.values():
    EFFECT_TYPES |= set(_types)
PROCESS_RULES = ({"process_spawn", "process_image_fallback_spawn"} | {f"process_{s}" for s in PROCESS_ACTIONS}
                 | {f"process_image_fallback_{s}" for s in PROCESS_ACTIONS})


def ground_truth(events: list[Event]) -> dict[str, str]:
    """dst event id -> true cause (the Sysmon process-start of its actor GUID)."""
    start_by_guid: dict[str, Event] = {}
    for e in events:
        if e.source_artifact == "sysmon" and e.event_type == EventType.PROCESS_START:
            g = e.attributes.get("object_guid")
            if g:
                start_by_guid.setdefault(g, e)
    truth: dict[str, str] = {}
    for e in events:
        if e.source_artifact != "sysmon" or e.event_type not in EFFECT_TYPES:
            continue
        g = e.attributes.get("actor_guid")
        src = start_by_guid.get(g or "")
        if src is not None and src.event_id != e.event_id and src.timestamp <= e.timestamp:
            truth[e.event_id] = src.event_id
    return truth


# ----------------------------------------------------------------- baselines
def _starts(events: list[Event]):
    return [e for e in events if e.event_type == EventType.PROCESS_START]


def v01_exact_ref_join(events: list[Event], window_s: float = 3600.0) -> dict[str, set[str]]:
    idx: dict[str, list[Event]] = defaultdict(list)
    for s in _starts(events):
        idx[s.object].append(s)
    pred: dict[str, set[str]] = defaultdict(set)
    for d in events:
        if d.event_type not in EFFECT_TYPES:
            continue
        for s in idx.get(d.actor, []):
            dt = (d.timestamp - s.timestamp).total_seconds()
            if s.event_id != d.event_id and 0 <= dt <= window_s:
                pred[d.event_id].add(s.event_id)
    return pred


def pid_nearest(events: list[Event], window_s: float = 86400.0) -> dict[str, set[str]]:
    from revenant.entities import split_process_ref

    idx: dict[str, tuple[list[float], list[Event]]] = {}
    for s in _starts(events):
        p = split_process_ref(s.object)
        if p and p[0]:
            ts, ev = idx.setdefault(f"{event_host(s)}|{p[0]}", ([], []))
            ts.append(s.timestamp.timestamp())
            ev.append(s)
    pred: dict[str, set[str]] = defaultdict(set)
    for d in events:
        if d.event_type not in EFFECT_TYPES:
            continue
        p = split_process_ref(d.actor)
        if not p or not p[0]:
            continue
        k = f"{event_host(d)}|{p[0]}"
        if k not in idx:
            continue
        ts, ev = idx[k]
        i = bisect.bisect_right(ts, d.timestamp.timestamp()) - 1
        while i >= 0 and ev[i].event_id == d.event_id:
            i -= 1
        if i >= 0 and d.timestamp.timestamp() - ts[i] <= window_s:
            pred[d.event_id].add(ev[i].event_id)
    return pred


def pid_image_nearest(events: list[Event], window_s: float = 86400.0,
                      image_window_s: float = 3600.0) -> dict[str, set[str]]:
    """PID-nearest; for an effect without a PID, the nearest earlier start of the same image on its host."""
    from revenant.entities import norm_path, split_process_ref

    pred = pid_nearest(events, window_s)
    idx: dict[str, tuple[list[float], list[Event]]] = {}
    for s in _starts(events):
        p = split_process_ref(s.object)
        img = norm_path(s.attributes.get("image") or (p[1] if p else ""))
        if img:
            ts, ev = idx.setdefault(f"{event_host(s)}|{img}", ([], []))
            ts.append(s.timestamp.timestamp())
            ev.append(s)
    for d in events:
        if d.event_type not in EFFECT_TYPES or d.event_id in pred:
            continue
        p = split_process_ref(d.actor)
        if not p or p[0] or not p[1]:
            continue  # has a PID (PID-nearest already decided) or no image either
        k = f"{event_host(d)}|{norm_path(p[1])}"
        if k not in idx:
            continue
        ts, ev = idx[k]
        i = bisect.bisect_right(ts, d.timestamp.timestamp()) - 1
        while i >= 0 and ev[i].event_id == d.event_id:
            i -= 1
        if i >= 0 and d.timestamp.timestamp() - ts[i] <= image_window_s:
            pred[d.event_id].add(ev[i].event_id)
    return pred


def ablated_rules(variant: str):
    """The GUID-blind rule set with one component removed."""
    from dataclasses import replace

    rules = default_rules(use_guids=False)
    if variant == "no_fallback":
        return [r for r in rules if not r.name.startswith("process_image_fallback")]
    if variant == "no_termination_guard":
        return [replace(r, respect_termination=False) for r in rules]
    if variant == "no_image_in_key":
        out = []
        for r in rules:
            if r.src_key is object_process_key and r.dst_key is actor_process_key:
                r = replace(r, src_key=_pid_only_object, dst_key=_pid_only_actor)
            out.append(r)
        return out
    return rules


ABLATIONS = ("no_fallback", "no_termination_guard", "no_image_in_key", "no_fusion")


def visible_events(events: list[Event]) -> list[Event]:
    """The fused, shadow-free event list the rule engine operates on."""
    g = ProvenanceGraph(backend="memory")
    g.add_events(events)
    fuse(g)
    return [e for e in g.events if e.event_id not in g.shadowed]


def revenant_edges(events: list[Event], variant: str = "full"
                   ) -> tuple[dict[str, set[str]], list[tuple[float, bool, str, str]]]:
    g = ProvenanceGraph(backend="memory")
    g.add_events(events)
    if variant != "no_fusion":
        fuse(g)
    rules = None if variant in ("full", "no_fusion") else ablated_rules(variant)
    RuleEngine(rules, use_guids=False, calibration=None).infer(g)  # hand-set confidences
    pred: dict[str, set[str]] = defaultdict(set)
    conf: dict[tuple[str, str], tuple[float, str]] = {}
    for e in g.edges:
        if e.rule_name in PROCESS_RULES:
            pred[e.dst_event_id].add(e.src_event_id)
            conf[(e.src_event_id, e.dst_event_id)] = (e.confidence, e.rule_name)
    return pred, conf  # type: ignore[return-value]


# ----------------------------------------------------------------- scoring
def score(pred: dict[str, set[str]], truth: dict[str, str]) -> dict[str, float]:
    tp = fp = 0
    hit: set[str] = set()
    for dst, true_src in truth.items():
        for s in pred.get(dst, ()):
            if s == true_src:
                tp += 1
                hit.add(dst)
            else:
                fp += 1
    n = len(truth)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = len(hit) / n if n else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": n - len(hit), "n_eval": n, "precision": round(precision, 4),
            "recall": round(recall, 4), "f1": round(f1, 4),
            "false_edge_rate": round(fp / (tp + fp), 4) if tp + fp else 0.0}


def counts(pred: dict[str, set[str]], truth: dict[str, str]) -> tuple[int, int, int, int]:
    """(tp, fp, effects with a correct cause, evaluable effects)."""
    tp = fp = hit = 0
    for dst, true_src in truth.items():
        got = pred.get(dst, ())
        ok = true_src in got
        tp += ok
        fp += len(got) - ok
        hit += ok
    return tp, fp, hit, len(truth)


def auroc(samples: list[tuple[float, bool]]) -> float | None:
    """Probability a correct edge outranks a wrong one (ties count half)."""
    pos = sorted(c for c, ok in samples if ok)
    neg = sorted(c for c, ok in samples if not ok)
    if not pos or not neg:
        return None
    import bisect as _b

    wins = 0.0
    for c in pos:
        lo = _b.bisect_left(neg, c)
        hi = _b.bisect_right(neg, c)
        wins += lo + 0.5 * (hi - lo)
    return round(wins / (len(pos) * len(neg)), 4)


def calibration(samples: list[tuple[float, bool]], bins: int = 10) -> dict:
    buckets: list[list[tuple[float, bool]]] = [[] for _ in range(bins)]
    for c, ok in samples:
        buckets[min(int(c * bins), bins - 1)].append((c, ok))
    rows, ece, n = [], 0.0, len(samples)
    for i, b in enumerate(buckets):
        if not b:
            continue
        mc = sum(c for c, _ in b) / len(b)
        acc = sum(ok for _, ok in b) / len(b)
        ece += len(b) / n * abs(mc - acc)
        rows.append({"bin": f"{i / bins:.1f}-{(i + 1) / bins:.1f}", "n": len(b),
                     "mean_confidence": round(mc, 4), "accuracy": round(acc, 4)})
    brier = sum((c - ok) ** 2 for c, ok in samples) / n if n else 0.0
    # ECE and Brier stay unrounded: displays round once (rounding 0.10544 to 0.1054 and then to
    # 0.105 is fine, but storing 0.1055 had turned it into 0.106)
    return {"ece": ece, "brier": brier, "auroc": auroc(samples), "n": n,
            "accuracy": round(sum(ok for _, ok in samples) / n, 4) if n else None, "bins": rows}


def score_by_type(pred: dict[str, set[str]], truth: dict[str, str], etype: dict[str, str]) -> dict:
    out = {}
    for t in sorted(set(etype.values())):
        sub = {d: s for d, s in truth.items() if etype[d] == t}
        r = score(pred, sub)
        out[t] = {"n_eval": r["n_eval"], "precision": r["precision"], "recall": r["recall"], "f1": r["f1"]}
    return out


MIN_RULE_N = 20  # rules seen fewer times keep their hand-set confidence


def fit_rule_table(samples: list[tuple[float, bool, str]]) -> dict[str, dict]:
    """Laplace-smoothed per-rule precision: (correct + 1) / (n + 2)."""
    by: dict[str, list[bool]] = defaultdict(list)
    for _c, ok, rule in samples:
        by[rule].append(ok)
    return {r: {"n": len(v), "confidence": round((sum(v) + 1) / (len(v) + 2), 4)}
            for r, v in sorted(by.items()) if len(v) >= MIN_RULE_N}


def apply_table(samples: list[tuple[float, bool, str]], table: dict[str, dict],
                only_table_rules: bool = False) -> list[tuple[float, bool]]:
    """Replace each edge's confidence by its rule's table constant, capped like the shipped loader.

    Edges whose rule is not in the table keep their hand-set confidence, or are dropped
    when ``only_table_rules`` (ECE restricted to the rules the table covers).
    """
    return [(min(table[r]["confidence"], MAX_CALIBRATED) if r in table else c, ok) for c, ok, r in samples
            if not only_table_rules or r in table]


def table_report(fit: list[tuple[float, bool, str]], test: list[tuple[float, bool, str]]) -> dict:
    """Held-out calibration of a table fitted on ``fit``: all edges, and only the rules it covers."""
    table = fit_rule_table(fit)
    covered = sum(r in table for _c, _ok, r in test)
    return {"table": table, "test": calibration(apply_table(test, table)),
            "test_table_rules_only": calibration(apply_table(test, table, only_table_rules=True)),
            "test_edges_left_handset": len(test) - covered}


def _bins(samples: list[tuple[float, bool]], bins: int = 10) -> list[list[float]]:
    out = [[0, 0.0, 0] for _ in range(bins)]
    for c, ok in samples:
        b = out[min(int(c * bins), bins - 1)]
        b[0] += 1
        b[1] += c
        b[2] += int(ok)
    return [[n, round(sc, 4), k] for n, sc, k in out]


def _hist(samples: list[tuple[float, bool]], nd: int) -> dict[str, list[int]]:
    h: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for c, ok in samples:
        h[f"{round(c, nd):.{nd}f}"][0 if ok else 1] += 1
    return dict(sorted(h.items()))


def evaluate(corpus: str, datasets: list[tuple[str, Path]]) -> tuple[dict, list[tuple[float, bool, str]]]:
    names = ("v01_exact_ref_join", "v01_exact_ref_join_fused", "pid_nearest", "pid_nearest_fused",
             "pid_image_nearest_fused", "revenant", *(f"revenant_{a}" for a in ABLATIONS))
    per_capture: list[dict] = []
    truth_all: dict[str, str] = {}
    etype: dict[str, str] = {}
    preds: dict[str, dict[str, set[str]]] = {k: {} for k in names}
    samples: list[tuple[float, bool, str]] = []
    sample_capture: list[int] = []  # per_capture index of each sample
    n_events = 0
    t_rev = 0.0
    for name, path in datasets:
        events, _st = load_cached(path, f"{corpus}-{name}")
        n_events += len(events)
        truth = ground_truth(events)
        truth_all.update(truth)
        types = {e.event_id: e.event_type.value for e in events}
        etype.update({d: types[d] for d in truth})
        vis = visible_events(events)
        cap: dict[str, dict[str, set[str]]] = {
            "v01_exact_ref_join": v01_exact_ref_join(events),
            "v01_exact_ref_join_fused": v01_exact_ref_join(vis),
            "pid_nearest": pid_nearest(events),
            "pid_nearest_fused": pid_nearest(vis),
            "pid_image_nearest_fused": pid_image_nearest(vis),
        }
        t0 = time.perf_counter()
        rp, conf = revenant_edges(events)
        t_rev += time.perf_counter() - t0
        cap["revenant"] = rp
        for a in ABLATIONS:
            cap[f"revenant_{a}"] = revenant_edges(events, a)[0]
        row = {"capture": name, "n_eval": len(truth), "by_type": dict(Counter(types[d] for d in truth))}
        for k, v in cap.items():
            preds[k].update(v)
            row[k] = list(counts(v, truth)[:3])  # tp, fp, hit
        per_capture.append(row)
        for (src, dst), (c, rule) in conf.items():
            if dst in truth:
                samples.append((c, truth[dst] == src, rule))
                sample_capture.append(len(per_capture) - 1)
    per_rule: dict[str, list[bool]] = defaultdict(list)
    for _c, ok, r in samples:
        per_rule[r].append(ok)
    res = {
        "corpus": corpus,
        "datasets": len(datasets),
        "events": n_events,
        "evaluable_effects": len(truth_all),
        "evaluable_by_type": dict(sorted(Counter(etype.values()).items())),
        "methods": {k: score(v, truth_all) for k, v in preds.items()},
        "by_effect_type": {k: score_by_type(preds[k], truth_all, etype)
                           for k in ("pid_nearest", "pid_nearest_fused", "pid_image_nearest_fused", "revenant")},
        "per_capture": per_capture,
        "revenant_calibration_handset": calibration([(c, ok) for c, ok, _ in samples]),
        "revenant_rule_accuracy": {r: {"n": len(v), "accuracy": round(sum(v) / len(v), 4)}
                                   for r, v in sorted(per_rule.items())},
        "revenant_rule_time_s": round(t_rev, 3),
    }
    res["_sample_capture"] = sample_capture  # removed before writing; used for per-capture calibration counts
    return res, samples


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-apt29", action="store_true")
    ap.add_argument("--extra", action="store_true",
                    help="also evaluate the opt-in compound corpora (LSASS campaign, Log4Shell, APT29 day 2)")
    ap.add_argument("--out", default="edges.json", help="results file name under results/")
    ap.add_argument("--shipped-table", type=Path,
                    help="rule_calibration.json to evaluate on every corpus (e.g. the table a sibling job refitted)")
    ap.add_argument("--write-calibration", action="store_true",
                    help="write the atomic-fitted rule table to src/revenant/data/rule_calibration.json")
    args = ap.parse_args(argv)
    out = {"benchmark": "causal_edges_vs_sysmon_guid", "environment": environment(), "corpora": []}
    t_start = time.perf_counter()
    corpora: dict[str, list[tuple[float, bool, str]]] = {}
    atomic = [(d.name, d.path) for d in atomic_datasets()]
    if atomic:
        r, corpora["otrf_atomic"] = evaluate("otrf_atomic", atomic)
        out["corpora"].append(r)
    if not args.no_apt29 and APT29_DIR.exists():
        r, corpora["otrf_apt29_day1"] = evaluate("otrf_apt29_day1", [("apt29_day1", APT29_DIR)])
        out["corpora"].append(r)
    if args.extra:
        for cname, caps in compound_corpora().items():
            r, smp = evaluate(cname, caps)
            corpora[cname] = smp
            if "otrf_atomic" in corpora:  # held-out test of the atomic-fitted table
                r["calibration_heldout_atomic_table"] = calibration(
                    apply_table(smp, fit_rule_table(corpora["otrf_atomic"])))
            out["corpora"].append(r)
    # cross-corpus calibration: fit per-rule precision on one corpus, test on another
    cc: dict = {}
    if "otrf_atomic" in corpora and "otrf_apt29_day1" in corpora:
        a_s, b_s = corpora["otrf_atomic"], corpora["otrf_apt29_day1"]
        cc["fit_otrf_atomic_test_otrf_apt29_day1"] = table_report(a_s, b_s)
        cc["fit_otrf_apt29_day1_test_otrf_atomic"] = table_report(b_s, a_s)
    for cname in ("otrf_lsass_campaign", "otrf_apt29_day2", "otrf_log4shell"):
        if cname in corpora and "otrf_atomic" in corpora:  # e.g. fallback rules fitted where they occur
            cc[f"fit_{cname}_test_otrf_atomic"] = table_report(corpora[cname], corpora["otrf_atomic"])
    if cc:
        out["calibration_cross_corpus"] = cc
    # per-capture calibration counts (atomic) for capture-bootstrapped ECE / AUROC / selective prediction
    atomic_res = next((c for c in out["corpora"] if c["corpus"] == "otrf_atomic"), None)
    if atomic_res is not None:
        smp, caps = corpora["otrf_atomic"], atomic_res["_sample_capture"]
        fit = fit_rule_table(corpora["otrf_apt29_day1"]) if "otrf_apt29_day1" in corpora else None
        by_cap: dict[int, list[tuple[float, bool, str]]] = defaultdict(list)
        for x, i in zip(smp, caps):
            by_cap[i].append(x)
        for i, row in enumerate(atomic_res["per_capture"]):
            got = by_cap.get(i, [])
            hs = [(c, ok) for c, ok, _ in got]
            row["calibration"] = {"handset_bins": _bins(hs), "handset_hist2": _hist(hs, 2)}
            if fit is not None:
                fs = apply_table(got, fit)
                row["calibration"]["fit_apt29_bins"] = _bins(fs)
                row["calibration"]["fit_apt29_hist"] = _hist(fs, 4)
    # the table users get: the previously shipped one (as loaded, capped) and this run's refit
    previous = {r: {"confidence": c} for r, c in load_calibration().items()}
    for c in out["corpora"]:
        c["calibration_previous_shipped_table"] = calibration(apply_table(corpora[c["corpus"]], previous))
        c.pop("_sample_capture", None)
    if "otrf_atomic" in corpora:
        table = fit_rule_table(corpora["otrf_atomic"])
        blob = json.dumps(table, sort_keys=True).encode("utf-8")
        src = provenance("bench-extended")
        fitted_on = {"corpus": "otrf_atomic", "captures": atomic_res["datasets"] if atomic_res else None,
                     "captures_with_effects": sum(1 for r in atomic_res["per_capture"] if r["n_eval"])
                     if atomic_res else None,
                     "effects": len(corpora["otrf_atomic"]), "run_id": src["run_id"], "commit": src["head_sha"]}
        out["atomic_fit_table"] = {"rules": table, "sha256": hashlib.sha256(blob).hexdigest(), "fitted_on": fitted_on,
                                   "written_to_package": bool(args.write_calibration)}
        if args.write_calibration:
            from common import ROOT

            dst = ROOT / "src" / "revenant" / "data" / "rule_calibration.json"
            dst.write_text(json.dumps({
                "fitted_on": fitted_on,
                "description": "OTRF Security-Datasets atomic Windows host captures; Sysmon GUIDs hidden at inference",
                "method": "Laplace-smoothed per-rule precision vs Sysmon GUID ground truth; capped at "
                          f"{MAX_CALIBRATED} when loaded",
                "min_n": MIN_RULE_N, "table_sha256": out["atomic_fit_table"]["sha256"], "rules": table},
                indent=1) + "\n", encoding="utf-8")
            print("[calibration]", dst)
    # the table this run ships (refitted here) or the one a sibling job refitted: held-out except on atomic
    shipped = out.get("atomic_fit_table", {}).get("rules") if args.write_calibration else None
    if shipped is None and args.shipped_table:
        shipped = json.loads(args.shipped_table.read_text(encoding="utf-8"))["rules"]
    if shipped is not None:
        for c in out["corpora"]:
            c["calibration_shipped_table"] = {**calibration(apply_table(corpora[c["corpus"]], shipped)),
                                              "held_out": c["corpus"] != "otrf_atomic"}
    for c in out["corpora"]:
        print(c["corpus"], c["events"], "events", c["evaluable_effects"], "evaluable")
        for m, sc in c["methods"].items():
            print(f"  {m:24s} P={sc['precision']:.3f} R={sc['recall']:.3f} F1={sc['f1']:.3f} "
                  f"FER={sc['false_edge_rate']:.3f}")
        print("  hand-set ECE", c["revenant_calibration_handset"]["ece"])
    for k, v in out.get("calibration_cross_corpus", {}).items():
        print(" ", k, "ECE", v["test"]["ece"], "rules-only", v["test_table_rules_only"]["ece"])
    out["source"] = provenance("bench-extended")
    out["runtime_s"] = round(time.perf_counter() - t_start, 1)
    write_json(args.out, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
