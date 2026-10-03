"""Render figures, results/RESULTS.md, results/headline.md and results/stats.json from results/*.json.

Every interval is 95% and every section names the workflow run its numbers
come from (the ``source`` block each benchmark writes).

* B1: capture-clustered percentile bootstrap (``stats.cluster_bootstrap``,
  10,000 resamples of captures, seed 7) for micro F1 and paired micro
  differences; per-capture macro-F1 differences with a paired bootstrap, an
  exact sign test and a Wilcoxon signed-rank test.
* Edge calibration: ECE, AUROC and selective-prediction precision bootstrapped
  over the atomic captures (10,000 multinomial resamples, numpy seed 7).
* B2, B3, B3b: Wilson intervals, exact McNemar tests. B5: Clopper-Pearson.
* B4: median and interquartile range of repeated runs.
* ATLAS: Wilson intervals on pooled counts and a bootstrap over attacks
  (computed by ``bench_atlas.py``).

``results/headline.md`` is the README/docs headline table; this script also
rewrites the README block between ``<!-- headline:start -->`` and
``<!-- headline:end -->`` so the two never drift.
"""

from __future__ import annotations

import json
import re

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from common import RESULTS, ROOT  # noqa: E402
from stats import (  # noqa: E402
    BOOT_REPS,
    BOOT_SEED,
    cluster_bootstrap,
    prf,
    sign_test,
    wilcoxon_signed_rank,
    wilson,
)

C = ["#2a78d6", "#eb6834", "#1baf7a", "#8a5cd1", "#c8a400"]
INK, MUTED, GRID = "#1b1f24", "#5d6570", "#e3e5e8"
plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED,
    "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True, "legend.frameon": False,
    "savefig.dpi": 130, "savefig.bbox": "tight",
})
METHOD_LABEL = {
    "v01_exact_ref_join_fused": "v0.1-style exact-ref join",
    "pid_nearest_fused": "PID-nearest",
    "pid_image_nearest_fused": "PID-then-image-nearest",
    "revenant": "REVENANT",
}
ABLATION_LABEL = {
    "revenant": "full engine",
    "revenant_no_fallback": "without image-only fallback rules",
    "revenant_no_image_in_key": "without image in the process key",
    "revenant_no_termination_guard": "without PID-reuse (termination) guard",
    "revenant_no_fusion": "without Sysmon/4688 fusion",
}
PAIRED = [("revenant", "pid_nearest_fused"), ("revenant", "pid_image_nearest_fused"),
          ("revenant", "revenant_no_fallback"), ("revenant", "revenant_no_image_in_key"),
          ("revenant", "revenant_no_termination_guard"), ("revenant", "revenant_no_fusion")]
STATS: dict = {"bootstrap": {"reps": BOOT_REPS, "seed": BOOT_SEED,
                             "b1": "random.Random(seed) resampling captures (stats.cluster_bootstrap)",
                             "calibration": "numpy default_rng(seed) multinomial resampling of captures"},
               "sources": {}}
MIN_CLUSTERS = 10  # a capture bootstrap over fewer clusters gives degenerate intervals


def load(name):
    p = RESULTS / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def src_line(d: dict | None, name: str) -> str:
    """Markdown note naming the run that produced a result file."""
    s = (d or {}).get("source") or {}
    STATS["sources"][name] = s or {"run_id": "unknown"}
    if s.get("run_url"):
        return f"Source: `results/{name}`, workflow `{s.get('workflow')}` run [{s['run_id']}]({s['run_url']}) " \
               f"(commit `{(s.get('head_sha') or '')[:7]}`)."
    if s.get("run_id") == "local":
        return f"Source: `results/{name}`, local run at commit `{(s.get('head_sha') or '')[:7]}`."
    return f"Source: `results/{name}` (no run id recorded)."


def run_ref(d: dict | None) -> str:
    s = (d or {}).get("source") or {}
    return f"[{s['run_id']}]({s['run_url']})" if s.get("run_url") else (s.get("run_id") or "-")


def fmt_ci(ci, nd: int = 3, signed: bool = False) -> str:
    if not ci:
        return "n/a"
    f = f"{{:+.{nd}f}}" if signed else f"{{:.{nd}f}}"
    return f"[{f.format(ci[0])}, {f.format(ci[1])}]"


def fmt_p(p: float) -> str:
    return f"{p:.2g}" if p < 0.001 else f"{p:.3f}"


# ------------------------------------------------------------------ B1
def _micro_f1(rows, m):
    tp = sum(r[m][0] for r in rows)
    fp = sum(r[m][1] for r in rows)
    hit = sum(r[m][2] for r in rows)
    n = sum(r["n_eval"] for r in rows)
    return prf(tp, fp, hit, n)[2]


def _macro(rows, m):
    return sum(prf(*r[m], r["n_eval"])[2] for r in rows) / len(rows)


def b1_stats(c: dict) -> dict:
    rows = [r for r in c.get("per_capture", []) if r["n_eval"]]
    out: dict = {"captures_with_effects": len(rows), "captures": c["datasets"]}
    if not rows:
        return out
    boot = len(rows) >= MIN_CLUSTERS
    if not boot:
        out["ci_note"] = f"n/a ({len(rows)} capture{'s' if len(rows) != 1 else ''} < {MIN_CLUSTERS})"
    methods = [k for k in rows[0] if isinstance(rows[0][k], list)]
    for m in methods:
        out[m] = {"f1_ci95": cluster_bootstrap(rows, lambda s, m=m: _micro_f1(s, m)) if boot else None,
                  "macro_f1": round(_macro(rows, m), 4),
                  "macro_f1_ci95": cluster_bootstrap(rows, lambda s, m=m: _macro(s, m)) if boot else None}
    out["paired"] = {}
    for a, b in PAIRED:
        if a not in rows[0] or b not in rows[0]:
            continue
        diffs = [prf(*r[a], r["n_eval"])[2] - prf(*r[b], r["n_eval"])[2] for r in rows]
        better, worse = sum(d > 1e-12 for d in diffs), sum(d < -1e-12 for d in diffs)
        out["paired"][f"{a}_vs_{b}"] = {
            "macro_f1_difference": round(sum(diffs) / len(diffs), 4),
            "macro_f1_difference_ci95": cluster_bootstrap(
                rows, lambda s, a=a, b=b: _macro(s, a) - _macro(s, b)) if boot else None,
            "micro_f1_difference": round(_micro_f1(rows, a) - _micro_f1(rows, b), 4),
            "micro_f1_difference_ci95": cluster_bootstrap(
                rows, lambda s, a=a, b=b: _micro_f1(s, a) - _micro_f1(s, b)) if boot else None,
            "captures_better": better, "captures_worse": worse, "ties": len(diffs) - better - worse,
            "sign_test_p": sign_test(better, worse), "wilcoxon_p": wilcoxon_signed_rank(diffs)}
    top3 = sorted(rows, key=lambda r: -r["n_eval"])[:3]
    out["top3_capture_share"] = round(sum(r["n_eval"] for r in top3) / sum(r["n_eval"] for r in rows), 3)
    rest = sorted(rows, key=lambda r: -r["n_eval"])[3:]
    if rest:
        out["micro_f1_without_top3"] = {m: round(_micro_f1(rest, m), 4) for m in ("revenant", "pid_nearest_fused")
                                        if m in rows[0]}
    return out


def fig_edges(d, md):
    corp = [c for c in d["corpora"] if c["evaluable_effects"]]
    STATS["b1"] = {c["corpus"]: b1_stats(c) for c in corp}
    methods = [m for m in METHOD_LABEL if all(m in c["methods"] for c in corp)]
    fig, ax = plt.subplots(figsize=(8.8, 3.8))
    w = 0.8 / len(methods)
    for j, m in enumerate(methods):
        xs = [i + (j - (len(methods) - 1) / 2) * w for i in range(len(corp))]
        vals = [c["methods"][m]["f1"] for c in corp]
        cis = [STATS["b1"][c["corpus"]].get(m, {}).get("f1_ci95") for c in corp]
        ax.bar(xs, vals, w * 0.9, color=C[j], label=METHOD_LABEL[m])
        for x, v, ci in zip(xs, vals, cis):
            if ci:  # error bars only where a capture bootstrap exists
                ax.errorbar([x], [v], yerr=[[max(0, v - ci[0])], [max(0, ci[1] - v)]], color=MUTED, capsize=2, lw=1)
            top = ci[1] if ci else v
            ax.text(x, top + 0.02, f"{v:.2f}", ha="center", va="bottom", fontsize=6.5, color=INK, rotation=90)
    ax.set_xticks(range(len(corp)), [f"{c['corpus'].replace('otrf_', '')}\n({c['evaluable_effects']:,} effects)"
                                     for c in corp], fontsize=8)
    ax.set_ylim(0, 1.3)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_ylabel("F1 vs Sysmon-GUID truth")
    ax.set_title("Causal-edge inference with GUIDs hidden (95% capture-bootstrap CI where >= 10 captures)",
                 loc="left", color=INK, fontsize=9.5)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=len(methods), fontsize=8)
    fig.savefig(RESULTS / "edges_f1.png")
    plt.close(fig)

    md += ["## B1 - causal edges vs Sysmon GUID ground truth", "", src_line(d, "edges.json"), "",
           "Sysmon GUIDs are hidden from every method and used as the truth, so this is a proxy for "
           "GUID-less sources (Sysmon events keep their PID and image). Baselines run on the same fused, "
           "shadow-free events REVENANT sees. CIs resample captures (10,000 reps, seed 7); corpora with "
           "fewer than 10 scorable captures report n/a.", "",
           "| corpus | captures (with effects) | effects | method | precision | recall | F1 [95% CI] | "
           "macro F1 [95% CI] |", "|---|---|---|---|---|---|---|---|"]
    for c in corp:
        st = STATS["b1"][c["corpus"]]
        for m in ("v01_exact_ref_join", "v01_exact_ref_join_fused", "pid_nearest", "pid_nearest_fused",
                  "pid_image_nearest_fused", "revenant"):
            if m not in c["methods"]:
                continue
            s = c["methods"][m]
            ci = st.get(m, {}).get("f1_ci95")
            mci = st.get(m, {}).get("macro_f1_ci95")
            mf = st.get(m, {}).get("macro_f1")
            md.append(f"| {c['corpus']} | {c['datasets']} ({st['captures_with_effects']}) | "
                      f"{c['evaluable_effects']:,} | {m} | {s['precision']:.3f} | {s['recall']:.3f} | "
                      f"{s['f1']:.3f} {fmt_ci(ci) if ci else '[' + st.get('ci_note', 'n/a') + ']'} | "
                      f"{mf if mf is not None else '-'} {fmt_ci(mci) if mci else ''} |")
    md.append("")
    md += ["### Ablation (one component removed)", "",
           "| corpus | variant | F1 [95% CI] | macro F1 [95% CI] |", "|---|---|---|---|"]
    for c in corp:
        st = STATS["b1"][c["corpus"]]
        for k, lab in ABLATION_LABEL.items():
            if k in c["methods"]:
                md.append(f"| {c['corpus']} | {lab} | {c['methods'][k]['f1']:.3f} "
                          f"{fmt_ci(st.get(k, {}).get('f1_ci95'))} | {st.get(k, {}).get('macro_f1', '-')} "
                          f"{fmt_ci(st.get(k, {}).get('macro_f1_ci95'))} |")
    md.append("")
    md += ["### Paired comparisons over captures (OTRF atomic)", "",
           "Per-capture F1 differences: macro difference with a paired capture bootstrap, exact sign test "
           "and Wilcoxon signed-rank test; micro (pooled-effect) difference with a paired capture bootstrap.", "",
           "| comparison | macro F1 diff [95% CI] | better / worse / tied captures | sign test p | "
           "Wilcoxon p | micro F1 diff [95% CI] |", "|---|---|---|---|---|---|"]
    for c in corp:
        for k, v in STATS["b1"][c["corpus"]].get("paired", {}).items():
            if not v["macro_f1_difference_ci95"]:
                continue
            md.append(f"| {k.replace('_vs_', ' vs ')} | {v['macro_f1_difference']:+.3f} "
                      f"{fmt_ci(v['macro_f1_difference_ci95'], signed=True)} | {v['captures_better']} / "
                      f"{v['captures_worse']} / {v['ties']} | {fmt_p(v['sign_test_p'])} | "
                      f"{fmt_p(v['wilcoxon_p'])} | {v['micro_f1_difference']:+.3f} "
                      f"{fmt_ci(v['micro_f1_difference_ci95'], signed=True)} |")
    for c in corp:
        st = STATS["b1"][c["corpus"]]
        if st.get("micro_f1_without_top3") and st["captures_with_effects"] >= MIN_CLUSTERS:
            w3 = st["micro_f1_without_top3"]
            md.append(f"\n{c['corpus']}: the 3 largest captures hold {st['top3_capture_share']:.0%} of the effects; "
                      f"without them micro F1 is {w3.get('revenant', '-')} (REVENANT) vs "
                      f"{w3.get('pid_nearest_fused', '-')} (PID-nearest).")
    md.append("")
    md += ["Per effect type (F1, with n):", "",
           "| corpus | effect | n | PID-nearest | PID-then-image | REVENANT |", "|---|---|---|---|---|---|"]
    for c in corp:
        bt = c["by_effect_type"]
        for t, r in bt["revenant"].items():
            b = bt.get("pid_nearest_fused", bt.get("pid_nearest", {})).get(t, {})
            pi = bt.get("pid_image_nearest_fused", {}).get(t, {})
            md.append(f"| {c['corpus']} | {t} | {r['n_eval']:,} | {b.get('f1', float('nan')):.3f} | "
                      f"{pi['f1']:.3f} | {r['f1']:.3f} |" if pi else
                      f"| {c['corpus']} | {t} | {r['n_eval']:,} | {b.get('f1', float('nan')):.3f} | - | {r['f1']:.3f} |")
    md.append("")


# ------------------------------------------------------------------ calibration
def _cap_arrays(rows, key):
    """captures x values matrices of positive/negative counts from per-capture histograms."""
    values = sorted({float(v) for r in rows for v in r["calibration"].get(key, {})}, reverse=True)
    idx = {v: i for i, v in enumerate(values)}
    pos = np.zeros((len(rows), len(values)))
    neg = np.zeros((len(rows), len(values)))
    for i, r in enumerate(rows):
        for v, (p, n) in r["calibration"].get(key, {}).items():
            pos[i, idx[float(v)]] += p
            neg[i, idx[float(v)]] += n
    return np.array(values), pos, neg


def _bins_array(rows, key):
    return np.array([r["calibration"][key] for r in rows], dtype=float)  # captures x 10 x [n, sum_conf, correct]


def _ece(b):  # b: ... x 10 x 3
    n = b[..., 0].sum(-1)
    return np.abs(b[..., 1] - b[..., 2]).sum(-1) / np.maximum(n, 1)


def _auroc(values, pos, neg):
    """AUROC from per-value counts (values sorted descending); ties count half. pos/neg: reps x values."""
    cum_neg_below = neg[..., ::-1].cumsum(-1)[..., ::-1] - neg  # negatives with lower confidence
    wins = (pos * (cum_neg_below + 0.5 * neg)).sum(-1)
    tot = pos.sum(-1) * neg.sum(-1)
    return np.where(tot > 0, wins / np.maximum(tot, 1), np.nan)


def _precision_at(values, pos, neg, q):
    """Precision of the highest-confidence edges covering at least share q of all edges."""
    kept_pos, kept = pos.cumsum(-1), (pos + neg).cumsum(-1)
    total = kept[..., -1:]
    first = (kept / np.maximum(total, 1) >= q - 1e-12).argmax(-1)
    take = np.take_along_axis
    kp = take(kept_pos, first[..., None], -1)[..., 0]
    k = take(kept, first[..., None], -1)[..., 0]
    return kp / np.maximum(k, 1)


def _ci(x):
    x = x[~np.isnan(x)]
    return [round(float(np.percentile(x, 2.5)), 4), round(float(np.percentile(x, 97.5)), 4)] if x.size else None


def calibration_bootstrap(rows) -> dict:
    rng = np.random.default_rng(BOOT_SEED)
    W = rng.multinomial(len(rows), [1 / len(rows)] * len(rows), size=BOOT_REPS).astype(float)  # reps x captures
    out: dict = {}
    hb = _bins_array(rows, "handset_bins")
    out["handset_ece"] = round(float(_ece(hb.sum(0))), 4)
    out["handset_ece_ci95"] = _ci(_ece(np.einsum("rc,cbk->rbk", W, hb)))
    if "fit_apt29_bins" in rows[0]["calibration"]:
        fb = _bins_array(rows, "fit_apt29_bins")
        out["fit_apt29_ece"] = round(float(_ece(fb.sum(0))), 4)
        out["fit_apt29_ece_ci95"] = _ci(_ece(np.einsum("rc,cbk->rbk", W, fb)))
        out["ece_difference_ci95"] = _ci(_ece(np.einsum("rc,cbk->rbk", W, fb)) - _ece(np.einsum("rc,cbk->rbk", W, hb)))
    for key, label in (("fit_apt29_hist", "fit_apt29"), ("handset_hist2", "handset")):
        if key not in rows[0]["calibration"]:
            continue
        values, pos, neg = _cap_arrays(rows, key)
        bp, bn = W @ pos, W @ neg
        out[f"{label}_auroc"] = round(float(_auroc(values, pos.sum(0), neg.sum(0))), 4)
        out[f"{label}_auroc_ci95"] = _ci(_auroc(values, bp, bn))
        for q in (0.5, 0.8, 0.9, 1.0):
            out[f"{label}_precision_at_coverage_{q}"] = round(float(_precision_at(values, pos.sum(0), neg.sum(0), q)), 4)
            out[f"{label}_precision_at_coverage_{q}_ci95"] = _ci(_precision_at(values, bp, bn, q))
    if "fit_apt29_hist" in rows[0]["calibration"]:
        vf, pf, nf = _cap_arrays(rows, "fit_apt29_hist")
        vh, ph, nh = _cap_arrays(rows, "handset_hist2")
        for q in (0.5, 0.8, 0.9):
            out[f"precision_gain_at_coverage_{q}_ci95"] = _ci(_precision_at(vf, W @ pf, W @ nf, q)
                                                              - _precision_at(vh, W @ ph, W @ nh, q))
    out["note"] = "hand-set histograms use confidences rounded to 2 dp; ECE uses exact per-bin sums"
    return out


def fig_calibration(d, md):
    cc = d.get("calibration_cross_corpus")
    if not cc:
        return
    atomic = next(c for c in d["corpora"] if c["corpus"] == "otrf_atomic")
    key = "fit_otrf_apt29_day1_test_otrf_atomic"
    rows = [r for r in atomic.get("per_capture", []) if r["n_eval"] and r.get("calibration")]
    boot = calibration_bootstrap(rows) if len(rows) >= MIN_CLUSTERS else {}
    STATS["calibration"] = {"atomic_capture_bootstrap": boot}
    fig, ax = plt.subplots(figsize=(4.8, 4.1))
    ax.plot([0, 1], [0, 1], color=MUTED, lw=1, ls="--", label="perfect calibration")
    for j, (label, cal) in enumerate([("hand-set confidences", atomic["revenant_calibration_handset"]),
                                      ("fitted on APT29 day 1", cc[key]["test"])]):
        xs = [b["mean_confidence"] for b in cal["bins"]]
        ys = [b["accuracy"] for b in cal["bins"]]
        ax.plot(xs, ys, color=C[j], lw=2, marker="o", ms=6, mec="white", mew=1.5,
                label=f"{label} (ECE {cal['ece']:.3f})")
        for x, y, b in zip(xs, ys, cal["bins"]):
            ax.annotate(f"{b['n']:,}", (x, y), xytext=(4, -10 if j else 6), textcoords="offset points", fontsize=6,
                        color=C[j])
    ax.set_xlim(0, 1.02)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("mean edge confidence (bin; labels = edges)")
    ax.set_ylabel("fraction of edges correct")
    ax.set_title("Edge-confidence reliability, OTRF atomic (held out)", loc="left", color=INK, fontsize=10)
    ax.legend(loc="lower right", fontsize=8)
    fig.savefig(RESULTS / "calibration.png")
    plt.close(fig)
    md += ["## Edge-confidence calibration", "", src_line(d, "edges.json"), "",
           "Per-rule constants fitted on one corpus, tested on another, capped at 0.99 as the loader caps them. "
           "Rules seen fewer than 20 times in the fitting corpus are not in its table and keep their hand-set, "
           "time-decayed confidence; the 'table rules only' column restricts ECE to the rules the table covers. "
           "When every test edge is correct (APT29) ECE only measures how close the constants are to 1.", "",
           "| test corpus | fitted on | ECE hand-set | ECE fitted (all edges) | ECE fitted (table rules only) | "
           "edges left hand-set | Brier | AUROC | test accuracy |", "|---|---|---|---|---|---|---|---|---|"]
    for k, v in cc.items():
        test = k.split("_test_")[1]
        fit = k.split("_test_")[0].removeprefix("fit_")
        hs = next(c for c in d["corpora"] if c["corpus"] == test)["revenant_calibration_handset"]
        t, tr = v["test"], v.get("test_table_rules_only", {})
        md.append(f"| {test} | {fit} | {hs['ece']:.3f} | {t['ece']:.3f} | {tr.get('ece', '-')} | "
                  f"{v.get('test_edges_left_handset', '-')} | {t.get('brier', '-')} | "
                  f"{t.get('auroc') if t.get('auroc') is not None else 'n/a (all correct)'} | {t.get('accuracy', '-')} |")
    if boot:
        md += ["", "Capture bootstrap on OTRF atomic (102 captures, APT29-fitted table vs hand-set): "
               f"ECE {boot.get('fit_apt29_ece')} {fmt_ci(boot.get('fit_apt29_ece_ci95'))} vs "
               f"{boot['handset_ece']} {fmt_ci(boot['handset_ece_ci95'])} (difference "
               f"{fmt_ci(boot.get('ece_difference_ci95'), signed=True)}); AUROC {boot.get('fit_apt29_auroc')} "
               f"{fmt_ci(boot.get('fit_apt29_auroc_ci95'))} vs hand-set {boot.get('handset_auroc')} "
               f"{fmt_ci(boot.get('handset_auroc_ci95'))}.", "",
               "**Selective prediction** (keep only the highest-confidence edges; precision at a given share of "
               "edges kept):", "",
               "| edges kept | hand-set confidences | APT29-fitted constants | gain [95% CI] |", "|---|---|---|---|"]
        for q in (0.5, 0.8, 0.9, 1.0):
            g = boot.get(f"precision_gain_at_coverage_{q}_ci95")
            md.append(f"| {q:.0%} | {boot.get(f'handset_precision_at_coverage_{q}')} "
                      f"{fmt_ci(boot.get(f'handset_precision_at_coverage_{q}_ci95'))} | "
                      f"{boot.get(f'fit_apt29_precision_at_coverage_{q}')} "
                      f"{fmt_ci(boot.get(f'fit_apt29_precision_at_coverage_{q}_ci95'))} | "
                      f"{fmt_ci(g, signed=True) if g else '-'} |")
    shipped = [(c["corpus"], c.get("calibration_shipped_table"), c.get("calibration_previous_shipped_table"))
               for c in d["corpora"]]
    if any(s for _, s, _ in shipped):
        t = d.get("atomic_fit_table", {})
        fo = t.get("fitted_on", {})
        STATS["calibration"]["shipped_table"] = {"sha256": t.get("sha256"), "fitted_on": fo,
                                                 "ece": {c: s.get("ece") for c, s, _ in shipped if s}}
        md += ["", f"**The table REVENANT ships** (`src/revenant/data/rule_calibration.json`, SHA-256 "
               f"`{(t.get('sha256') or '')[:12]}…`) is refitted in this run on OTRF atomic "
               f"({fo.get('captures_with_effects')} captures with effects, {fo.get('effects'):,} edges). Its ECE "
               "on every corpus (held out except atomic), and that of the table shipped before this run:", "",
               "| corpus | shipped table ECE | held out | previous table ECE |", "|---|---|---|---|"]
        for cname, s, prev in shipped:
            if s:
                md.append(f"| {cname} | {s['ece']:.3f} | {'yes' if s.get('held_out') else 'no (in-sample)'} | "
                          f"{prev['ece']:.3f} |" if prev else f"| {cname} | {s['ece']:.3f} | - | - |")
    md += ["", "Story confidence and grades are *not* calibrated: they are a documented, hand-weighted sum "
           "(see Limitations).", ""]


# ------------------------------------------------------------------ B2
def fig_stories(d, md):
    s = d["all"]
    methods = [("chronological", "chronological timeline"), ("flat_suspicion", "flat, suspicion-sorted"),
               ("revenant", "REVENANT stories")]
    fig, ax = plt.subplots(figsize=(6.4, 3.3))
    ks = [1, 3, 5]
    offsets = {"chronological": 0, "flat_suspicion": 9, "revenant": -9}
    for j, (m, lab) in enumerate(methods):
        ys = [s[m][f"hit@{k}"] for k in ks]
        lo = [y - s[m][f"hit@{k}_ci95"][0] for k, y in zip(ks, ys)]
        hi = [s[m][f"hit@{k}_ci95"][1] - y for k, y in zip(ks, ys)]
        xs = [k + (j - 1) * 0.08 for k in ks]
        ax.errorbar(xs, ys, yerr=[lo, hi], color=C[j], lw=2, marker="o", ms=6, mec="white", mew=1.5, capsize=3,
                    label=lab)
        ax.annotate(f"{ys[-1]:.2f}", (xs[-1], ys[-1]), xytext=(8, offsets[m]), textcoords="offset points",
                    va="center", fontsize=8, color=C[j])
    ax.set_xticks(ks, [f"budget {k}x median story" for k in ks], fontsize=8)
    ax.set_ylim(-0.02, 1)
    ax.set_xlim(0.7, 5.7)
    ax.set_ylabel("captures with labelled technique found")
    ax.set_title(f"Equal reading budget, {s['captures']} labelled OTRF captures (95% Wilson CI)", loc="left",
                 color=INK, fontsize=10)
    ax.legend(loc="upper left", fontsize=8)
    fig.savefig(RESULTS / "stories_hitk.png")
    plt.close(fig)
    t = s["revenant_vs_flat_suspicion"]
    md += ["## B2 - story ranking vs flat timelines (OTRF atomic, ATT&CK labels from metadata)", "",
           src_line(d, "stories.json"), "",
           "Every method gets the same event budget (k x the capture's median story size). The story-unit view "
           "gives the flat list exactly as many events as REVENANT's top-k whole stories contain. Note: 'found' "
           "uses REVENANT's own ATT&CK heuristics, and the shipped calibration table was fitted on the same "
           "captures.", "",
           "| method | hit@1 [95% CI] | hit@3 [95% CI] | hit@5 [95% CI] | story-unit hit@1 / @3 / @5 | reached | "
           "median events read |", "|---|---|---|---|---|---|---|"]
    for m, lab in methods:
        r = s[m]
        md.append(f"| {lab} | {r['hit@1']:.3f} {fmt_ci(r['hit@1_ci95'], 2)} | {r['hit@3']:.3f} "
                  f"{fmt_ci(r['hit@3_ci95'], 2)} | {r['hit@5']:.3f} {fmt_ci(r['hit@5_ci95'], 2)} | "
                  f"{r['story_hit@1']:.3f} / {r['story_hit@3']:.3f} / {r['story_hit@5']:.3f} | "
                  f"{r['found']}/{s['captures']} | {r['median_events_to_evidence']} |")
    md += ["", "Paired exact McNemar, REVENANT vs flat suspicion-sorted (captures found by REVENANT only / flat "
           "only, p):", ""]
    md.append(", ".join(f"{k}: {v['revenant_only']}/{v['flat_only']}, p={fmt_p(v['mcnemar_p'])}" for k, v in t.items()))
    h1 = t["hit@1"]
    verdict = ("lower, not significant" if h1["mcnemar_p"] >= 0.05 else "significantly lower") \
        if s["revenant"]["hit@1"] < s["flat_suspicion"]["hit@1"] else \
        ("higher, not significant" if h1["mcnemar_p"] >= 0.05 else "significantly higher")
    md.append(f"\nVerdict at hit@1: {verdict} (p={fmt_p(h1['mcnemar_p'])}).\n")
    STATS["b2"] = {"captures": s["captures"], "revenant_vs_flat": t, "hit@1_verdict": verdict,
                   **{m: {k: s[m][k] for k in s[m] if k.startswith(("hit@", "story_hit@"))} for m, _ in methods}}


# ------------------------------------------------------------------ B3 / B3b
B3_METHODS = [("baseline_1102_104", "1102/104 query (SIEM baseline)"),
              ("sigma_equivalent", "Sigma-equivalent (1102/104, Sysmon 2, logging-disable keys, 4719)"),
              ("revenant_v1_1", "REVENANT 1.1.0 indicators (before logging_stopped)"),
              ("revenant", "REVENANT, all indicators"),
              ("revenant_excl_log_cleared", "REVENANT without log_cleared"),
              ("revenant_logging_tamper", "REVENANT logging-tamper indicators only"),
              ("revenant_high_only", "REVENANT, high severity only")]


def _method_rows(d, md, key: str):
    md += ["| detector | precision [95% CI] | recall [95% CI] | F1 | TP | FP | FN |", "|---|---|---|---|---|---|---|"]
    STATS[key] = {"methods": {}}
    for m, lab in B3_METHODS:
        r = d["methods"].get(m)
        if not r:
            continue
        pci = r.get("precision_wilson95") or wilson(r["tp"], r["tp"] + r["fp"])
        rci = r.get("recall_wilson95") or wilson(r["tp"], r["tp"] + r["fn"])
        STATS[key]["methods"][m] = {"precision": r["precision"], "recall": r["recall"], "f1": r["f1"],
                                    "precision_ci95": pci, "recall_ci95": rci}
        md.append(f"| {lab} | {r['precision']:.3f} {fmt_ci(pci, 2)} | {r['recall']:.3f} {fmt_ci(rci, 2)} | "
                  f"{r['f1']:.3f} | {r['tp']} | {r['fp']} | {r['fn']} |")
    tests = d.get("paired_tests") or {}
    if tests:
        md += ["", "Exact McNemar tests (REVENANT-only / other-only files, p):", ""]
        for k, v in tests.items():
            if k.endswith(("_positives", "_all")):
                other, scope = k.removeprefix("revenant_vs_").rsplit("_", 1)
                md.append(f"- REVENANT vs {dict(B3_METHODS).get(other, other)}, {scope}: "
                          f"{v['revenant_only']}/{v['other_only']}, p={fmt_p(v['mcnemar_p'])}")
        STATS[key]["paired_tests"] = tests


def af_table(d, md):
    md += ["## B3 - anti-forensics on EVTX-ATTACK-SAMPLES (file level)", "", src_line(d, "antiforensics.json"), "",
           f"{d['readable_files']} readable .evtx files, only {d['positives']} labelled as log/timestamp tampering "
           f"by file name, so every interval is wide. Parser: {d['parser']['records']:,} records "
           f"({d['parser'].get('records_per_s', '-')} records/s on the runner); "
           f"{d['parser']['coverage_supported_channels']:.1%} of the {d['parser']['supported_channel_records']:,} "
           "records in supported channels mapped. The `logging_stopped` indicator was written after seeing this "
           "benchmark's misses, so its before/after gain here is not a held-out estimate (B3b is).", ""]
    _method_rows(d, md, "b3")
    md += ["", f"Missed positives: {', '.join(d['missed_positives']) or 'none'}", ""]


def b3b_table(d, md):
    md += ["## B3b - anti-forensics on OTRF captures labelled T1562.002 (capture level)", "",
           src_line(d, "antiforensics_b3b.json"), "",
           f"Positives: the {d['positives']} host captures linked by the six OTRF metadata entries mapped to "
           f"T1562.002 (Disable Windows Event Logging); negatives: {d['negatives']} labelled atomic captures mapped "
           "to neither T1562 nor T1070. Many OTRF captures contain a genuine 1102/104 from the author clearing logs "
           "before recording, and benign Sysmon EID 2 events are common, so detector variants are shown "
           "separately. These captures were in the development corpus (B1/B2), so this is not a blind test of the "
           "older indicators.", ""]
    _method_rows(d, md, "b3b")
    el = d.get("entry_level", {})
    if el:
        md += ["", "Metadata-entry level (an entry is found when any of its captures is flagged): " +
               "; ".join(f"{m} {v['found']}/{v['entries']} {fmt_ci(v['recall_wilson95'], 2)}" for m, v in el.items()
                         if m in dict(B3_METHODS))]
        STATS["b3b"]["entry_level"] = el
    md += ["", f"Indicator counts, positive captures: {d.get('indicator_counts_positive_captures')}; negative "
           f"captures: {d.get('indicator_counts_negative_captures')}.",
           f"Missed positives (all indicators): {', '.join(d.get('missed_positives') or []) or 'none'}", ""]


def b3_combined(b3, b3b, md):
    """Recall over both label sources (10 EVTX files + 17 OTRF captures)."""
    if not (b3 and b3b):
        return
    out = {}
    for m, _ in B3_METHODS:
        r1, r2 = b3["methods"].get(m), b3b["methods"].get(m)
        if r1 and r2:
            tp, n = r1["tp"] + r2["tp"], r1["tp"] + r1["fn"] + r2["tp"] + r2["fn"]
            out[m] = {"tp": tp, "positives": n, "recall": round(tp / n, 4), "recall_wilson95": wilson(tp, n)}
    STATS["b3_b3b_combined_recall"] = out
    if not out:
        return
    md += ["Recall over both label sources combined (" + str(next(iter(out.values()))["positives"]) +
           " positives): " + "; ".join(f"{m} {v['tp']}/{v['positives']} {fmt_ci(v['recall_wilson95'], 2)}"
                                       for m, v in out.items()), ""]


# ------------------------------------------------------------------ B4
def fig_scale(d, md):
    sc = d["rule_engine_scaling"]
    fig, ax = plt.subplots(figsize=(5.6, 3.6))
    common = sc.get("loglog_slope_v02_common_range")
    v02_label = (f"v0.2 indexed (slope {common} on 500-4,000; {sc['loglog_slope_v02']} overall)" if common is not None
                 else f"v0.2 indexed (slope {sc['loglog_slope_v02']})")
    for j, (k, lab) in enumerate([("v01_pairwise", f"v0.1 pairwise (slope {sc['loglog_slope_v01']})"),
                                  ("v02_indexed", v02_label)]):
        rows = sc[k]
        ys = [max(r["seconds"], 1e-3) for r in rows]
        lo = [max(r["seconds"] - min(r.get("runs", [r["seconds"]])), 0) for r in rows]
        hi = [max(max(r.get("runs", [r["seconds"]])) - r["seconds"], 0) for r in rows]
        ax.errorbar([r["n"] for r in rows], ys, yerr=[lo, hi], color=C[j], lw=2, marker="o", ms=6, mec="white",
                    mew=1.5, capsize=2, label=lab)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("events (time-ordered prefix of APT29 day 1)")
    ax.set_ylabel("rule inference, seconds (median, min-max)")
    ax.set_title("Rule-engine scaling on real events", loc="left", color=INK, fontsize=10)
    ax.legend(fontsize=7)
    fig.savefig(RESULTS / "scaling.png")
    plt.close(fig)
    e = d["end_to_end"]
    a = e["analysis_s"]
    total = a if isinstance(a, dict) else {"median": a, "q1": a, "q3": a, "runs": [a]}
    stages = ", ".join(f"{k} {v:.1f} s" for k, v in e["stage_s"].items())
    env = d.get("environment", {})
    STATS["b4"] = {"analysis_s": total, "events": e["events"], "slopes": {
        "v01": sc["loglog_slope_v01"], "v02_common_range": common, "v02_overall": sc["loglog_slope_v02"]},
        "platform": env.get("platform"), "python": env.get("python")}
    md += ["## B4 - scale (APT29 day 1, full capture)", "", src_line(d, "scale.json"), "",
           f"- Machine: {env.get('platform')}, Python {env.get('python')}.",
           f"- {e['events']:,} normalized events from {e['raw_rows']:,} raw rows "
           f"(mapping coverage {e['mapping_coverage']:.1%})",
           f"- analysis of pre-parsed events (JSON parsing excluded): median {total['median']} s "
           f"(IQR {total['q1']}-{total['q3']} s over {len(total['runs'])} runs; {e['events_per_s']:,.0f} events/s); "
           f"median stage times: {stages}",
           f"- {e['edges']:,} causal edges, {e['corroborations']:,} cross-artefact corroborations, "
           f"{e['stories']} stories, {e['indicators']} tamper/coverage indicators",
           f"- rule engine log-log slope on the common 500-4,000-event range: v0.1 {sc['loglog_slope_v01']} vs "
           f"v0.2 {common if common is not None else 'n/a'}; v0.2 over 500-{e['events']:,} events: "
           f"{sc['loglog_slope_v02']}; v0.1 extrapolated to the full capture: "
           f"~{sc['v01_extrapolated_full_capture_s']:,.0f} s", ""]


# ------------------------------------------------------------------ B5
def live_table(d, md):
    k = d["kernel_truth"]
    STATS["b5"] = {"events": d["events"], "checks_passed": sum(d["checks"].values()), "checks": len(d["checks"]),
                   "edges_agree": [k["tp"], k["inferred"]], "precision_ci95": k.get("precision_clopper_pearson95"),
                   "best_story": d.get("best_story")}
    b = d.get("best_story") or {}
    md += ["## B5 - live auditd capture in CI (consistency check)", "", src_line(d, "live_auditd.json"), "",
           f"{d['events']} events; {sum(d['checks'].values())}/{len(d['checks'])} chain checks pass; the best story "
           f"ranks {b.get('rank', '-')} with coverage {b.get('coverage', '-')}, grade {b.get('grade', '-')}; "
           f"{k['tp']}/{k['inferred']} inferred process edges agree with auditd's own pid/ppid "
           f"(95% Clopper-Pearson {fmt_ci(k.get('precision_clopper_pearson95'))}). The parser reads the same "
           "fields, so this is an end-to-end regression check, not an independent accuracy measurement.", ""]


# ------------------------------------------------------------------ C: ATLAS
def atlas_table(d, md):
    s = d["paper_vs_spreadsheet"]
    p = d["paper"]
    md += ["## C - ATLAS reproduction (Alsaheel et al., USENIX Security 2021)", "", src_line(d, "atlas_repro.json"),
           "", f"Paper figures: entity level from {p['source']['entity']}; event level from {p['source']['event']}", "",
           "| source | entity P / R / F1 | event P / R / F1 |", "|---|---|---|"]
    md.append(f"| paper | {p['entity']['precision']:.4f} / {p['entity']['recall']:.4f} / {p['entity']['f1']:.4f} | "
              f"{p['event']['precision']:.4f} / {p['event']['recall']:.4f} / {p['event']['f1']:.4f} |")
    for lab, key in (("released per-attack counts (Table 4 rows), macro", "macro"),
                     ("released per-attack counts, pooled (micro)", "micro")):
        e, v = s[f"entity_{key}"], s[f"event_{key}"]
        md.append(f"| {lab} | {e['precision']:.4f} / {e['recall']:.4f} / {e['f1']:.4f} | "
                  f"{v['precision']:.4f} / {v['recall']:.4f} / {v['f1']:.4f} |")
    rr = d.get("evaluate_py_rerun")
    if rr and rr.get("n_attacks"):
        e, v = rr["entity_macro"], rr["event_macro"]
        md.append(f"| authors' `evaluate.py` re-run on the released outputs ({rr['n_attacks']} attacks, macro) | "
                  f"{e['precision']:.4f} / {e['recall']:.4f} / {e['f1']:.4f} | "
                  f"{v['precision']:.4f} / {v['recall']:.4f} / {v['f1']:.4f} |")
        sel = rr.get("selection", {})
        md += ["", f"**Which run scores each attack.** {sel.get('rule', '')} M4_h1's error: "
               f"`{sel.get('m4_h1_error', '-')}`."]
        h1 = sel.get("host1_only")
        if h1:
            md.append(f"Host-1-only figures (not comparable with the paper; n={len(h1['attacks'])}): entity F1 "
                      f"{h1['entity_macro']['f1']:.4f}, event F1 {h1['event_macro']['f1']:.4f}.")
        t4 = d.get("table4_vs_rerun", {})
        if t4:
            lg = t4.get("largest_event_tp_difference") or ["-", 0]
            same = t4.get("event_counts_identical", [])
            same4 = [m for m in ("precision", "recall", "f1") if round(v[m], 4) == p["event"][m]]
            off4 = [f"{m} {v[m]:.4f} vs {p['event'][m]:.4f}" for m in ("precision", "recall", "f1") if m not in same4]
            md.append(f"\nThe macro event figures match Table 4's average to 4 decimal places for "
                      f"{', '.join(same4) or 'no metric'}{' (' + '; '.join(off4) + ')' if off4 else ''}, but per-attack "
                      f"event counts equal "
                      f"Table 4 only for {', '.join(same) or 'no attack'} ({len(same)} of {len(t4['attacks'])}); the "
                      f"largest difference is {lg[0]} ({lg[1]:+d} TP). Entity counts differ for every attack because "
                      "`evaluate.py` counts unique graph words, not the spreadsheet's entities.")
        STATS["atlas"] = {"evaluate_py_rerun": {k: rr[k] for k in ("n_attacks", "entity_macro", "event_macro")},
                          "selection_rule": sel.get("rule"), "host1_only": h1,
                          "table4_event_counts_identical": t4.get("event_counts_identical")}
    chk = d.get("event_totals_match_spreadsheet", {})
    if chk:
        ok = sum(v["match"] for v in chk.values())
        md.append(f"\nReleased model outputs contain exactly the spreadsheet's event totals for {ok}/{len(chk)} attacks.")
    mr = d.get("model_rerun", {}).get("summary")
    if mr:
        md += ["", f"**Model re-run.** `atlas.py` (testing mode, released `model.h5`, TensorFlow 2.3 in "
               f"`python:3.7-slim`, no network) ran on {mr['atlas_py_ok']}/{mr['test_graphs']} test graphs; graph "
               f"words were identical to the release for {mr['graph_words_identical']} and the model's predicted "
               f"words for {mr['predicted_words_identical']}. Scored by `evaluate.py` without the authors' manual "
               f"cleaning (raw predicted words), the re-run gives entity F1 "
               f"{mr.get('rerun_raw_entity_macro', {}).get('f1', '-')} and event F1 "
               f"{mr.get('rerun_raw_event_macro', {}).get('f1', '-')} (the released raw predictions: "
               f"{mr.get('released_raw_entity_macro', {}).get('f1', '-')} / "
               f"{mr.get('released_raw_event_macro', {}).get('f1', '-')}); the paper's figures need the hand-cleaned "
               "list, which a re-run cannot regenerate."]
        diff = [f"{a} ({r['experiment']}: {r.get('prediction_flips')} word predictions differ, max |p diff| "
                f"{r.get('max_abs_probability_difference')})"
                for a, v in d["model_rerun"]["attacks"].items() for r in v["runs"].values()
                if r.get("ok") and not r.get("predicted_identical")]
        if diff:
            md.append("Differences from the release: " + "; ".join(diff) + ".")
        STATS.setdefault("atlas", {})["model_rerun"] = mr
    pr = d.get("atlasv2_probe")
    if pr:
        st = ", ".join(f"{q['method']} {q.get('status')}" for q in pr.get("requests", []))
        interp = pr.get("interpretation", "")
        md += ["", f"**ATLASv2 link** ({pr['url']}, probed {pr['probed_at_utc']}): {st}. "
               f"{interp[:1].upper() + interp[1:]}."]
        STATS.setdefault("atlas", {})["atlasv2_probe"] = {"statuses": st, "link_alive": pr.get("link_alive")}
    md.append("")


def atlas_revenant_table(d, md):
    m = d["methods"]
    md += ["## C2 - REVENANT scored under the ATLAS protocol", "", src_line(d, "atlas_revenant.json"), "",
           "Symptom-seeded stories over ATLAS's own test logs (labels stripped), entities mapped to ATLAS's label "
           "strings (docs/atlas-mapping.md) and scored by the authors' `evaluate.py`. ATLAS's released predictions "
           "were cleaned by hand; REVENANT's are automatic. CIs: bootstrap over the 10 attacks (10,000 reps, "
           "seed 7) for macro F1, Wilson on pooled counts.", "",
           "| method | entity P / R / F1 (macro) | entity F1 [95% CI] | pooled entity P [CI] / R [CI] | "
           "event P / R / F1 (macro) | event F1 [95% CI] |", "|---|---|---|---|---|---|"]
    labels = {"atlas_released": "ATLAS (released, hand-cleaned)", "revenant": "REVENANT story",
              "revenant_uncapped": "REVENANT story, no cap", "backtracker": "BackTracker-style reachability",
              "symptom_only": "symptom (and its DNS aliases) only"}
    for k, lab in labels.items():
        v = m.get(k)
        if not v or not v.get("n_attacks"):
            continue
        e, ev, pe = v["entity_macro"], v["event_macro"], v["entity_pooled"]
        md.append(f"| {lab} | {e['precision']:.3f} / {e['recall']:.3f} / {e['f1']:.3f} | "
                  f"{fmt_ci(v['entity_macro_f1_bootstrap95'])} | {pe['precision']:.3f} "
                  f"{fmt_ci(pe['precision_wilson95'], 2)} / {pe['recall']:.3f} {fmt_ci(pe['recall_wilson95'], 2)} | "
                  f"{ev['precision']:.3f} / {ev['recall']:.3f} / {ev['f1']:.3f} | "
                  f"{fmt_ci(v['event_macro_f1_bootstrap95'])} |")
    pa = d.get("paired_vs_atlas", {}).get("revenant", {})
    pb = d.get("paired_revenant_vs_backtracker", {})
    lines = []
    for name, block in (("vs ATLAS", pa), ("vs BackTracker-style reachability", pb)):
        for lvl in ("entity", "event"):
            x = block.get(lvl)
            if x:
                lines.append(f"REVENANT {name}, {lvl} F1: mean difference {x['mean_f1_difference']:+.3f} "
                             f"{fmt_ci(x['bootstrap95'], signed=True)}, better on {x['a_better']}/{x['n']} attacks, "
                             f"worse on {x['b_better']} (sign test p={fmt_p(x['sign_test_p'])})")
    md += ["", *[f"- {x}" for x in lines], ""]
    STATS["atlas_revenant"] = {k: {kk: v.get(kk) for kk in ("entity_macro", "event_macro",
                                                              "entity_macro_f1_bootstrap95",
                                                              "event_macro_f1_bootstrap95")}
                               for k, v in m.items() if v.get("n_attacks")}
    STATS["atlas_revenant"]["paired_vs_atlas"] = pa
    STATS["atlas_revenant"]["paired_vs_backtracker"] = pb


# ------------------------------------------------------------------ headline
def headline(data: dict) -> list[str]:
    """README/docs headline table, generated so it cannot drift from the result files."""
    rows = ["| Benchmark (public data, ground truth) | REVENANT | Best baseline | Verdict | Source run |",
            "|---|---|---|---|---|"]
    e = data.get("edges.json")
    if e and "b1" in STATS and "otrf_atomic" in STATS["b1"]:
        c = next(x for x in e["corpora"] if x["corpus"] == "otrf_atomic")
        st = STATS["b1"]["otrf_atomic"]
        pr = st["paired"].get("revenant_vs_pid_nearest_fused", {})
        pi = st["paired"].get("revenant_vs_pid_image_nearest_fused", {})
        best = max(("pid_nearest_fused", "pid_image_nearest_fused"), key=lambda m: c["methods"].get(m, {}).get("f1", 0))
        rows.append(
            f"| B1 causal edges, OTRF atomic ({st['captures']} captures, {st['captures_with_effects']} with scorable "
            f"effects; Sysmon GUIDs hidden as a proxy for GUID-less sources) | F1 {c['methods']['revenant']['f1']:.3f} "
            f"{fmt_ci(st['revenant']['f1_ci95'], 2)}; macro {st['revenant']['macro_f1']:.3f} | "
            f"{METHOD_LABEL[best]} {c['methods'][best]['f1']:.3f} {fmt_ci(st[best]['f1_ci95'], 2)}; macro "
            f"{st[best]['macro_f1']:.3f} | macro difference vs PID-nearest {pr.get('macro_f1_difference', 0):+.3f} "
            f"{fmt_ci(pr.get('macro_f1_difference_ci95'), 3, True)}, sign test p={fmt_p(pr.get('sign_test_p', 1))}"
            + (f"; vs PID-then-image {pi['macro_f1_difference']:+.3f} "
               f"{fmt_ci(pi.get('macro_f1_difference_ci95'), 3, True)}, p={fmt_p(pi['sign_test_p'])}" if pi else "")
            + f" | {run_ref(e)} |")
        easy = [x for x in e["corpora"] if x["corpus"] != "otrf_atomic" and x["evaluable_effects"]]
        if easy:
            lo = min(x["methods"]["revenant"]["f1"] for x in easy)
            hi = max(x["methods"]["revenant"]["f1"] for x in easy)
            blo = min(x["methods"]["pid_nearest_fused"]["f1"] for x in easy)
            rows.append(f"| B1, APT29 day 1 + day 2, LSASS (7), Log4Shell | F1 {lo:.3f}-{hi:.3f} | PID-nearest "
                        f"{blo:.3f}-1.000 | no difference (fewer than 10 captures per corpus: no CI) | {run_ref(e)} |")
    cal = STATS.get("calibration", {})
    boot = cal.get("atomic_capture_bootstrap", {})
    if boot.get("fit_apt29_ece") is not None:
        rows.append(f"| Edge calibration, fit APT29 -> test atomic | ECE {boot['fit_apt29_ece']:.3f} "
                    f"{fmt_ci(boot.get('fit_apt29_ece_ci95'))}, AUROC {boot.get('fit_apt29_auroc')} "
                    f"{fmt_ci(boot.get('fit_apt29_auroc_ci95'), 2)} | hand-set ECE {boot['handset_ece']:.3f} "
                    f"{fmt_ci(boot.get('handset_ece_ci95'))} | improved, not solved | {run_ref(e)} |")
    s = data.get("stories.json")
    if s:
        a = s["all"]
        h1 = a["revenant_vs_flat_suspicion"]["hit@1"]
        rows.append(f"| B2 story ranking, {a['captures']} labelled captures, equal budget | hit@1 "
                    f"{a['revenant']['hit@1']:.2f} {fmt_ci(a['revenant']['hit@1_ci95'], 2)} | flat suspicion-sorted "
                    f"{a['flat_suspicion']['hit@1']:.2f} {fmt_ci(a['flat_suspicion']['hit@1_ci95'], 2)} | "
                    f"{STATS['b2']['hit@1_verdict']} (McNemar p={fmt_p(h1['mcnemar_p'])}) | {run_ref(s)} |")
    for fname, label in (("antiforensics.json", "B3 anti-forensics, EVTX-ATTACK-SAMPLES"),
                         ("antiforensics_b3b.json", "B3b anti-forensics, OTRF T1562.002 captures")):
        x = data.get(fname)
        if not x:
            continue
        r, b, sg = x["methods"]["revenant"], x["methods"]["baseline_1102_104"], x["methods"].get("sigma_equivalent")
        t = (x.get("paired_tests") or {}).get("revenant_vs_sigma_equivalent_positives", {})
        n_pos = x.get("positives")
        rows.append(f"| {label} ({n_pos} positives) | recall {r['recall']:.2f} "
                    f"{fmt_ci(r.get('recall_wilson95'), 2)}, precision {r['precision']:.2f} "
                    f"{fmt_ci(r.get('precision_wilson95'), 2)} | 1102/104 recall {b['recall']:.2f}; Sigma-equivalent "
                    f"recall {sg['recall']:.2f}, precision {sg['precision']:.2f} | vs Sigma-equivalent on positives "
                    f"{t.get('revenant_only', '-')}/{t.get('other_only', '-')} discordant, p={fmt_p(t.get('mcnemar_p', 1))} "
                    f"| {run_ref(x)} |" if sg else "")
    ar = data.get("atlas_repro.json")
    if ar and ar.get("evaluate_py_rerun"):
        v, en = ar["evaluate_py_rerun"]["event_macro"], ar["evaluate_py_rerun"]["entity_macro"]
        mr = (ar.get("model_rerun") or {}).get("summary", {})
        t4 = ar.get("table4_vs_rerun", {})
        n_att = len(t4.get("attacks", {}))
        n_diff = n_att - len(t4.get("event_counts_identical", []))
        rows.append(f"| C ATLAS paper, authors' release and `evaluate.py` | event F1 {v['f1']:.4f}, entity F1 "
                    f"{en['f1']:.3f}; model re-run (TF 2.3) identical predictions on "
                    f"{mr.get('predicted_words_identical', '-')}/{mr.get('test_graphs', '-')} test graphs | paper "
                    f"0.9988 / 0.9376 | recomputed: macro event figures match Table 4's average; per-attack event "
                    f"counts differ for {n_diff} of {n_att} attacks | {run_ref(ar)} |")
    rv = data.get("atlas_revenant.json")
    if rv:
        r, at = rv["methods"]["revenant"], rv["methods"].get("atlas_released", {})
        pa = rv.get("paired_vs_atlas", {}).get("revenant", {}).get("entity", {})
        rows.append(f"| C2 REVENANT under the ATLAS protocol (10 attacks) | entity F1 {r['entity_macro']['f1']:.3f} "
                    f"{fmt_ci(r['entity_macro_f1_bootstrap95'], 2)}, event F1 {r['event_macro']['f1']:.3f} "
                    f"{fmt_ci(r['event_macro_f1_bootstrap95'], 2)} | ATLAS (hand-cleaned) "
                    f"{at.get('entity_macro', {}).get('f1', 0):.3f} / {at.get('event_macro', {}).get('f1', 0):.4f} | "
                    f"**worse** on {pa.get('b_better', '-')}/{pa.get('n', '-')} attacks (sign test "
                    f"p={fmt_p(pa.get('sign_test_p', 1))}) | {run_ref(rv)} |")
    lv = data.get("live_auditd.json")
    if lv:
        k = lv["kernel_truth"]
        rows.append(f"| B5 live auditd capture in CI (scripted benign sequence) | "
                    f"{sum(lv['checks'].values())}/{len(lv['checks'])} chain checks; {k['tp']}/{k['inferred']} edges "
                    f"agree {fmt_ci(k.get('precision_clopper_pearson95'), 2)} | - | consistency check, not accuracy | "
                    f"{run_ref(lv)} |")
    return [r for r in rows if r]


def write_headline(lines: list[str]) -> None:
    text = "\n".join(lines) + "\n"
    (RESULTS / "headline.md").write_text("<!-- generated by benchmarks/make_figures.py -->\n" + text, encoding="utf-8")
    readme = ROOT / "README.md"
    s = readme.read_text(encoding="utf-8")
    new = re.sub(r"(<!-- headline:start -->\n).*?(<!-- headline:end -->)", lambda m: m.group(1) + text + m.group(2),
                 s, flags=re.S)
    if new != s:
        readme.write_text(new, encoding="utf-8")


def main() -> int:
    md = ["<!-- --8<-- [start:results] -->",
          "Generated by `python benchmarks/make_figures.py` from `results/*.json`; CIs are 95%. Each section names "
          "the workflow run that produced it.", ""]
    data = {n: load(n) for n in ("edges.json", "stories.json", "antiforensics.json", "antiforensics_b3b.json",
                                 "scale.json", "live_auditd.json", "atlas_repro.json", "atlas_revenant.json")}
    if data["edges.json"]:
        fig_edges(data["edges.json"], md)
        fig_calibration(data["edges.json"], md)
    if data["stories.json"]:
        fig_stories(data["stories.json"], md)
    if data["antiforensics.json"]:
        af_table(data["antiforensics.json"], md)
    if data["antiforensics_b3b.json"]:
        b3b_table(data["antiforensics_b3b.json"], md)
    b3_combined(data["antiforensics.json"], data["antiforensics_b3b.json"], md)
    if data["scale.json"]:
        fig_scale(data["scale.json"], md)
    if data["live_auditd.json"]:
        live_table(data["live_auditd.json"], md)
    if data["atlas_repro.json"]:
        atlas_table(data["atlas_repro.json"], md)
    if data["atlas_revenant.json"]:
        atlas_revenant_table(data["atlas_revenant.json"], md)
    md.append("<!-- --8<-- [end:results] -->")
    (RESULTS / "RESULTS.md").write_text("# REVENANT benchmark results\n\n" + "\n".join(md) + "\n", encoding="utf-8")
    write_headline(headline(data))
    (RESULTS / "stats.json").write_text(json.dumps(STATS, indent=1, default=str) + "\n", encoding="utf-8")
    print("[results] RESULTS.md, headline.md, stats.json + figures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
