"""C -- reproduce the ATLAS paper's headline numbers (Alsaheel et al., USENIX Security 2021).

ATLAS reports, averaged over its 10 attacks (S1-S4 single-host, M1-M6
multi-host), entity-level precision 91.06%, recall 97.29%, F1 93.76% and
event-level P/R/F1 around 99.9%. The authors released, per experiment, the
trained ``model.h5``, the model outputs (``output/eval_*.json``), their
``evaluate.py`` and the per-attack spreadsheet behind the paper tables.

This script performs three checks, each recorded separately so a failure in
one never hides the others:

1. ``paper_vs_spreadsheet`` -- recompute per-attack P/R/F1 from the
   spreadsheet's TP/FP/FN counts and average them (macro), plus the pooled
   (micro) values; compare with the paper's abstract.
2. ``released_outputs`` -- read every released ``eval_*.json`` and record its
   event count and the authors' cleaned prediction vs malicious labels; the
   event totals must equal the spreadsheet's ground-truth event totals.
3. ``evaluate_py_logs`` -- if the workflow ran the authors' ``evaluate.py`` on
   the released outputs (``--eval-logs DIR``), parse the metrics it printed.

Usage::

    python benchmarks/atlas_repro.py --root DIR [--eval-logs DIR] [--out results/atlas_repro.json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PAPER = {"entity": {"precision": 0.9106, "recall": 0.9729, "f1": 0.9376},
         "event": {"precision": 0.9988, "recall": 0.9989, "f1": 0.9988},
         "source": "Alsaheel et al., ATLAS, USENIX Security 2021 (abstract and Table 4)"}


def _prf(tp: float, fp: float, fn: float) -> dict[str, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


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
    out: dict = {"attacks": {}, "n_attacks": len(rows)}
    for level in ("entity", "event"):
        per = {a: _prf(v[level]["tp"], v[level]["fp"], v[level]["fn"]) for a, v in rows.items()}
        for a in per:
            out["attacks"].setdefault(a, {})[level] = {**rows[a][level], **per[a]}
        macro = {m: round(sum(p[m] for p in per.values()) / len(per), 4) for m in ("precision", "recall", "f1")}
        tot = {k: sum(v[level][k] for v in rows.values()) for k in ("tp", "fp", "fn")}
        out[f"{level}_macro"] = macro
        out[f"{level}_micro"] = _prf(tot["tp"], tot["fp"], tot["fn"])
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
                    "sequences": len(d[3]), "predicted_entities": sorted(cleaned),
                    "malicious_entities": sorted(malicious),
                    "entity_tp": len(cleaned & malicious), "entity_fp": len(cleaned - malicious),
                    "entity_fn": len(malicious - cleaned)}
    return out


_METRIC = re.compile(r"(precision|recall|f1|f-1|f1-score|accuracy)\D{0,20}?([01]?\.\d+)", re.I)


def eval_logs(d: Path) -> dict:
    out = {}
    for f in sorted(d.glob("*.log")):
        text = f.read_text(encoding="utf-8", errors="replace")
        out[f.stem] = {"metrics": [(m.group(1).lower(), float(m.group(2))) for m in _METRIC.finditer(text)][:40],
                       "tail": text[-1500:]}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, required=True, help="download_atlas.py destination")
    ap.add_argument("--eval-logs", type=Path)
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "results" / "atlas_repro.json")
    a = ap.parse_args(argv)
    res: dict = {"benchmark": "atlas_reproduction", "paper": PAPER,
                 "source": {"repo": "purseclab/ATLAS", "commit": "e46096d1947e4f059e73a0ac2b9a9707812fd4bc"}}
    sheet = spreadsheet(a.root / "paper_experiments" / "docs" / "atlas.xlsx")
    res["paper_vs_spreadsheet"] = sheet
    outs = released_outputs(a.root / "paper_experiments")
    res["released_outputs"] = outs
    # event totals of the held-out test outputs must match the spreadsheet's ground truth
    checks = {}
    for rel, o in outs.items():
        m = re.match(r"([SM])(\d)", o["dataset"] or "")
        if not m or "testing" not in rel:
            continue
        aid = f"{m.group(1)}-{m.group(2)}"
        if aid in sheet["attacks"]:
            checks[rel] = o["events"] == sheet["attacks"][aid]["event"]["total"]
    res["event_totals_match_spreadsheet"] = checks
    if a.eval_logs and a.eval_logs.is_dir():
        res["evaluate_py_logs"] = eval_logs(a.eval_logs)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    em = sheet["entity_macro"]
    print("entity macro (recomputed):", em, "paper:", PAPER["entity"])
    print("entity micro (recomputed):", sheet["entity_micro"])
    print("event macro (recomputed):", sheet["event_macro"])
    print("event totals match:", sum(checks.values()), "/", len(checks))
    ok = all(abs(sheet["entity_macro_minus_paper"][k]) <= 0.001 for k in em) and checks and all(checks.values())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
