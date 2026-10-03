"""C -- reproduce the ATLAS paper's headline numbers (Alsaheel et al., USENIX Security 2021).

ATLAS reports, averaged over its 10 attacks (S-1..S-4 single host, M-1..M-6
two hosts), entity-level precision/recall/F1 91.06/97.29/93.76% (abstract,
p. 3005; Table 4 Avg row, p. 3016) and event-level 99.88/99.89/99.88% (Table 4
Avg row, p. 3016; Table 5 ATLAS row, p. 3017; the 99.88% precision also in
§6.2.1, p. 3015). The abstract gives no event-level figure. The authors released,
per experiment, the trained ``model.h5``, the model outputs
(``output/eval_*.json``), their ``evaluate.py`` and the per-attack spreadsheet
behind Table 4.

Checks, each recorded separately so a failure in one never hides the others:

1. ``paper_vs_spreadsheet`` -- per-attack P/R/F1 from the spreadsheet's counts,
   averaged unrounded and rounded once (macro), plus pooled (micro) values.
2. ``released_outputs`` -- every released ``eval_*.json``: event count,
   hand-cleaned predictions and labels; event totals vs the spreadsheet.
3. ``evaluate_py_rerun`` -- the counts the authors' ``evaluate.py`` printed on
   their released outputs (one log per experiment folder), the rule that
   picks one folder per attack (``selection``), and a per-attack diff against
   Table 4 (``table4_vs_rerun``).
4. ``model_rerun`` -- ``model.h5`` re-executed by ``atlas.py`` in a TensorFlow 2.3
   container (``benchmarks/atlas_rerun.py``): fresh vs released outputs, and the
   model's raw (uncleaned) predicted words scored by ``evaluate.py``.
5. ``atlasv2_probe`` -- HTTP status of the ATLASv2 download link (no download).

Exit status is non-zero unless the spreadsheet reproduces the paper's entity
averages, ``evaluate.py`` produced counts for all 10 attacks with an event
macro within 1e-4 of the paper, every failed ``evaluate.py`` run is on the
allowlist, and (when ``--model-rerun`` is given) the ``model_rerun`` block exists.

Usage::

    python benchmarks/atlas_repro.py --root DIR [--eval-logs DIR] [--model-rerun DIR] [--probe FILE]
        [--released-dir DIR] [--out results/atlas_repro.json]
    python benchmarks/atlas_repro.py --root DIR --released-only --out FILE    # one attack's eval_*.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stats import provenance  # noqa: E402

PAPER = {"entity": {"precision": 0.9106, "recall": 0.9729, "f1": 0.9376},
         "event": {"precision": 0.9988, "recall": 0.9989, "f1": 0.9988},
         "source": {"entity": "abstract (p. 3005) and Table 4, Avg row (p. 3016)",
                    "event": "Table 4, Avg row (p. 3016); Table 5, ATLAS row (p. 3017); precision also in "
                             "§6.2.1 (p. 3015). The abstract gives no event-level figure.",
                    "paper": "Alsaheel et al., ATLAS: A Sequence-based Learning Approach for Attack "
                             "Investigation, USENIX Security 2021, pp. 3005-3022"}}
ATTACKS = [f"S-{i}" for i in range(1, 5)] + [f"M-{i}" for i in range(1, 7)]
# experiment folder whose evaluate.py scores each attack: the h2 folder of a multi-host attack
# holds both hosts' eval_*.json (ATLAS README: copy the h1 output into the h2 output folder)
PICK = {f"S-{i}": f"S{i}" for i in range(1, 5)} | {f"M-{i}": f"M{i}_h2" for i in range(1, 7)}
HOST1 = {f"S-{i}": f"S{i}" for i in range(1, 5)} | {f"M-{i}": f"M{i}_h1" for i in range(1, 7)}
SELECTION_RULE = (
    "Each multi-host attack (M-1..M-6) is scored from its h2 experiment folder, where ATLAS's procedure "
    "(README: copy the h1 output into the h2 output folder) makes evaluate.py read both hosts' outputs; "
    "its event totals equal the paper's (e.g. M-1: 251,675 events in h2 vs 121,114 in h1). The h1 folders "
    "score host 1 alone. In the release, M4_h1's eval_*.json has no cleaned predicted entities (field 0 is "
    "empty), so evaluate.py stops there with an error.")
# experiments whose evaluate.py failure is known and explained; anything else fails the job
ALLOWED_FAILURES = {"M4_h1": "released eval_*.json has an empty cleaned-prediction list (field 0); "
                             "evaluate.py exits with 'ERROR: Please add the cleaned predicted entities...'"}
EVENT_TOLERANCE = 1e-4


def _prf(tp: float, fp: float, fn: float) -> dict[str, float]:
    """Unrounded precision, recall, F1."""
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0}


def _round(d: dict[str, float], nd: int = 4) -> dict[str, float]:
    return {k: round(v, nd) for k, v in d.items()}


def _macro(per: list[dict[str, float]]) -> dict[str, float]:
    """Average unrounded per-attack values; round once."""
    return {m: round(sum(p[m] for p in per) / len(per), 4) for m in ("precision", "recall", "f1")}


def spreadsheet(xlsx: Path) -> dict:
    import openpyxl

    ws = openpyxl.load_workbook(xlsx, data_only=True).worksheets[0]
    rows = {}
    for r in ws.iter_rows(values_only=True):
        if not r or not isinstance(r[0], str) or not re.fullmatch(r"[SM]-\d", r[0].strip()):
            continue
        a = r[0].strip()
        # columns: id, ent total, ent rel, ent irrel, TP, TN, FP#, FP%, FN#, FN%, ev total, ev rel, ev irrel,
        #          ev TP, ev TN, ev FP, ev FN, ...
        rows[a] = {"entity": {"tp": r[4], "tn": r[5], "fp": r[6], "fn": r[8], "total": r[1], "relevant": r[2]},
                   "event": {"tp": r[13], "tn": r[14], "fp": r[15], "fn": r[16], "total": r[10], "relevant": r[11]},
                   "sheet_entity_prf": [r[17], r[18], r[19]], "sheet_event_prf": [r[20], r[21], r[22]]}
    out: dict = {"attacks": {}, "n_attacks": len(rows),
                 "note": "the spreadsheet's per-attack counts equal Table 4's rows (p. 3016)"}
    for level in ("entity", "event"):
        per = {a: _prf(v[level]["tp"], v[level]["fp"], v[level]["fn"]) for a, v in rows.items()}
        for a in per:
            out["attacks"].setdefault(a, {})[level] = {**rows[a][level], **_round(per[a])}
        macro = _macro(list(per.values()))
        tot = {k: sum(v[level][k] for v in rows.values()) for k in ("tp", "fp", "fn")}
        out[f"{level}_macro"] = macro
        out[f"{level}_micro"] = _round(_prf(tot["tp"], tot["fp"], tot["fn"]))
        out[f"{level}_macro_minus_paper"] = {m: round(macro[m] - PAPER[level][m], 4) for m in macro}
    return out


def released_outputs(root: Path) -> dict:
    out = {}
    for f in sorted(root.rglob("eval_*.json")):
        if "__MACOSX" in f.parts:
            continue
        d = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        rel = f.relative_to(root).as_posix()
        exp = rel.split("/output/")[0]
        cleaned, malicious = set(d[0]), set(d[1])
        out[rel] = {"experiment": exp, "dataset": d[7] if len(d) > 7 else None, "events": len(d[6]),
                    "sequences": len(d[3]), "symptom": d[2], "predicted_entities": sorted(cleaned),
                    "malicious_entities": sorted(malicious),
                    "entity_tp": len(cleaned & malicious), "entity_fp": len(cleaned - malicious),
                    "entity_fn": len(malicious - cleaned)}
    return out


_COUNT = re.compile(r"## Result \((entity|event)\) ##\s*TP: (\d+)\s*TN: (\d+)\s*FP: (\d+)\s*FN: (\d+)")


def eval_logs(d: Path) -> dict:
    """Parse the TP/TN/FP/FN blocks printed by the authors' evaluate.py, one log per experiment."""
    out = {}
    for f in sorted(d.glob("*.log")):
        text = f.read_text(encoding="utf-8", errors="replace")
        counts = {m.group(1): dict(zip(("tp", "tn", "fp", "fn"), map(int, m.groups()[1:])))
                  for m in _COUNT.finditer(text)}
        err = next((ln.strip() for ln in text.splitlines() if ln.startswith(("ERROR", "Traceback", "exit "))), "")
        out[f.stem] = {"counts": counts, "ok": set(counts) == {"entity", "event"},
                       "error": "" if counts else (err or text[-300:].strip())}
    return out


def _attack_rows(logs: dict, pick: dict[str, str]) -> dict[str, dict]:
    per = {}
    for aid, exp in pick.items():
        c = logs.get(exp, {}).get("counts", {})
        if set(c) == {"entity", "event"}:
            per[aid] = {"experiment": exp,
                        **{lvl: {**c[lvl], **_round(_prf(c[lvl]["tp"], c[lvl]["fp"], c[lvl]["fn"]))} for lvl in c}}
    return per


def rerun_summary(logs: dict) -> dict:
    """Per attack: S-1..S-4 from their folder, M-1..M-6 from the h2 folder (it scores both hosts)."""
    per = _attack_rows(logs, PICK)
    out: dict = {"attacks": per, "n_attacks": len(per)}
    for lvl in ("entity", "event"):
        if per:
            out[f"{lvl}_macro"] = _macro([_prf(v[lvl]["tp"], v[lvl]["fp"], v[lvl]["fn"]) for v in per.values()])
            out[f"{lvl}_macro_minus_paper"] = {m: round(out[f"{lvl}_macro"][m] - PAPER[lvl][m], 4)
                                               for m in ("precision", "recall", "f1")}
    return out


def selection(logs: dict) -> dict:
    """The h1/h2 rule, the experiment used per attack, the M4_h1 error and host-1-only figures."""
    h1 = _attack_rows(logs, HOST1)
    out: dict = {"rule": SELECTION_RULE, "experiment_per_attack": PICK,
                 "allowed_failures": ALLOWED_FAILURES,
                 "m4_h1_error": logs.get("M4_h1", {}).get("error", "not run")}
    if h1:
        out["host1_only"] = {
            "label": "HOST 1 ONLY -- not comparable with the paper: multi-host attacks scored on host 1 alone "
                     f"(n={len(h1)}; attacks whose h1 run failed are left out)",
            "attacks": sorted(h1),
            **{f"{lvl}_macro": _macro([_prf(v[lvl]["tp"], v[lvl]["fp"], v[lvl]["fn"]) for v in h1.values()])
               for lvl in ("entity", "event")}}
    return out


def table4_vs_rerun(sheet: dict, rerun: dict) -> dict:
    """Per attack, evaluate.py re-run counts minus Table 4's counts (the spreadsheet rows)."""
    out: dict = {"attacks": {}}
    for aid in ATTACKS:
        r, s = rerun["attacks"].get(aid), sheet["attacks"].get(aid)
        if not r or not s:
            continue
        row = {}
        for lvl in ("entity", "event"):
            row[lvl] = {k: {"table4": s[lvl][k], "rerun": r[lvl][k], "diff": r[lvl][k] - s[lvl][k]}
                        for k in ("tp", "fp", "fn")}
        row["identical"] = all(v["diff"] == 0 for lvl in ("entity", "event") for v in row[lvl].values())
        out["attacks"][aid] = row
    ev = {a: v["event"]["tp"]["diff"] for a, v in out["attacks"].items()}
    out["attacks_identical"] = sum(v["identical"] for v in out["attacks"].values())
    out["event_counts_identical"] = sorted(a for a, v in out["attacks"].items()
                                           if all(x["diff"] == 0 for x in v["event"].values()))
    out["largest_event_tp_difference"] = max(ev.items(), key=lambda kv: abs(kv[1])) if ev else None
    return out


def model_rerun(d: Path) -> dict:
    """Merge the per-attack summaries of benchmarks/atlas_rerun.py with evaluate.py's counts."""
    logs = eval_logs(d / "logs") if (d / "logs").is_dir() else {}
    out: dict = {"attacks": {}, "environment": "python:3.7-slim (3.7.17), tensorflow 2.3.0, keras 2.4.3, "
                 "fuzzywuzzy 0.18.0, numpy 1.16.6, networkx 2.2 (ci/atlas/tf.Dockerfile), --network none"}
    for f in sorted(d.glob("*.json")):
        s = json.loads(f.read_text(encoding="utf-8"))
        a = s["attack"]
        aid = f"{a[0]}-{a[1:]}"
        row = {"runs": s["runs"], "failed": s["failed"], "complete": s["complete"]}
        for variant in ("rerun_raw", "released_raw"):
            c = logs.get(f"{variant}_{aid}", {})
            if c.get("ok"):
                row[variant] = {lvl: {**c["counts"][lvl], **_round(_prf(c["counts"][lvl]["tp"], c["counts"][lvl]["fp"],
                                                                         c["counts"][lvl]["fn"]))}
                                for lvl in ("entity", "event")}
            elif c:
                row[variant] = {"error": c.get("error", "")}
        out["attacks"][aid] = row
    runs = [r for v in out["attacks"].values() for r in v["runs"].values()]
    ok = [r for r in runs if r.get("ok")]
    out["summary"] = {
        "test_graphs": len(runs), "atlas_py_ok": len(ok),
        "graph_words_identical": sum(bool(r.get("graph_words_identical")) for r in ok),
        "predicted_words_identical": sum(bool(r.get("predicted_identical")) for r in ok),
        "max_abs_probability_difference": max((r.get("max_abs_probability_difference", 0.0) for r in ok),
                                              default=None),
        "attacks_complete": sum(v["complete"] for v in out["attacks"].values()),
    }
    for variant in ("rerun_raw", "released_raw"):
        per = [v[variant] for v in out["attacks"].values() if isinstance(v.get(variant), dict) and "entity" in v[variant]]
        if per:
            out["summary"][f"{variant}_n"] = len(per)
            for lvl in ("entity", "event"):
                out["summary"][f"{variant}_{lvl}_macro"] = _macro(
                    [_prf(p[lvl]["tp"], p[lvl]["fp"], p[lvl]["fn"]) for p in per])
    out["note"] = ("rerun_raw / released_raw score the model's raw predicted graph words (prediction = 1) with "
                   "evaluate.py, i.e. without the authors' manual cleaning step; the paper's numbers use the "
                   "hand-cleaned field 0, which a re-run cannot regenerate.")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, required=True, help="download_atlas.py destination")
    ap.add_argument("--eval-logs", type=Path)
    ap.add_argument("--model-rerun", type=Path, help="per-attack atlas_rerun.py summaries + logs/")
    ap.add_argument("--probe", type=Path, help="ATLASv2 link probe JSON")
    ap.add_argument("--released-dir", type=Path, help="released_outputs JSON files written per attack")
    ap.add_argument("--released-only", action="store_true", help="write released_outputs for --root and stop")
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "results" / "atlas_repro.json")
    a = ap.parse_args(argv)
    if a.released_only:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(released_outputs(a.root / "paper_experiments"), indent=1) + "\n", encoding="utf-8")
        return 0
    res: dict = {"benchmark": "atlas_reproduction", "paper": PAPER,
                 "atlas_release": {"repo": "purseclab/ATLAS", "commit": "e46096d1947e4f059e73a0ac2b9a9707812fd4bc"},
                 "source": provenance("atlas-repro")}
    sheet = spreadsheet(a.root / "paper_experiments" / "docs" / "atlas.xlsx")
    res["paper_vs_spreadsheet"] = sheet
    outs = released_outputs(a.root / "paper_experiments")
    if a.released_dir and a.released_dir.is_dir():
        for f in sorted(a.released_dir.glob("*.json")):
            outs.update(json.loads(f.read_text(encoding="utf-8")))
    res["released_outputs"] = dict(sorted(outs.items()))
    # event totals of the held-out test outputs must match the spreadsheet's ground truth
    # (multi-host attacks: the sheet's total is the sum over the h1 and h2 test logs)
    per_attack: dict[str, dict[str, int]] = {}
    for o in outs.values():
        m = re.match(r"([SM])(\d)", o["dataset"] or "")
        if m:
            per_attack.setdefault(f"{m.group(1)}-{m.group(2)}", {})[o["dataset"]] = o["events"]
    checks = {k: {"released_events": sum(v.values()), "sheet_events": sheet["attacks"][k]["event"]["total"],
                  "match": sum(v.values()) == sheet["attacks"][k]["event"]["total"]}
              for k, v in sorted(per_attack.items()) if k in sheet["attacks"]}
    res["event_totals_match_spreadsheet"] = checks
    problems: list[str] = []
    em = sheet["entity_macro"]
    if not all(abs(sheet["entity_macro_minus_paper"][k]) <= 0.001 for k in em):
        problems.append(f"spreadsheet entity macro {em} does not reproduce the paper")
    if a.eval_logs and a.eval_logs.is_dir():
        logs = eval_logs(a.eval_logs)
        res["evaluate_py_logs"] = logs
        rr = rerun_summary(logs)
        res["evaluate_py_rerun"] = rr
        rr["selection"] = selection(logs)
        res["table4_vs_rerun"] = table4_vs_rerun(sheet, rr)
        bad = sorted(k for k, v in logs.items() if not v["ok"] and k not in ALLOWED_FAILURES)
        if bad:
            problems.append(f"evaluate.py failed outside the allowlist: {bad}")
        if rr["n_attacks"] != len(ATTACKS):
            problems.append(f"evaluate.py counts for {rr['n_attacks']}/{len(ATTACKS)} attacks")
        elif any(abs(sum(_prf(v["event"]["tp"], v["event"]["fp"], v["event"]["fn"])[m] for v in rr["attacks"].values())
                     / len(rr["attacks"]) - PAPER["event"][m]) > EVENT_TOLERANCE for m in ("precision", "recall", "f1")):
            problems.append(f"evaluate.py event macro {rr['event_macro']} differs from the paper by more than "
                            f"{EVENT_TOLERANCE}")
        print("evaluate.py re-run on released outputs:", {k: v for k, v in rr.items() if k not in ("attacks", "selection")})
        print("Table 4 vs re-run: identical for", res["table4_vs_rerun"]["attacks_identical"], "attacks")
    if a.model_rerun is not None:
        mr = model_rerun(a.model_rerun) if a.model_rerun.is_dir() else {"attacks": {}}
        if not mr["attacks"]:
            problems.append("model_rerun block missing: no atlas_rerun.py summaries")
        res["model_rerun"] = mr
        print("model re-run:", mr.get("summary"))
    if a.probe and a.probe.exists():
        res["atlasv2_probe"] = json.loads(a.probe.read_text(encoding="utf-8"))
    res["problems"] = problems
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    print("entity macro (recomputed):", em, "paper:", PAPER["entity"])
    print("entity micro (recomputed):", sheet["entity_micro"])
    print("event macro (recomputed):", sheet["event_macro"])
    print("event totals match:", sum(c["match"] for c in checks.values()), "/", len(checks))
    for p in problems:
        print("PROBLEM:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
