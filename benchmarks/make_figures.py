"""Render README/docs figures, results/RESULTS.md and results/stats.json from results/*.json.

Confidence intervals: B1 uses a capture-clustered percentile bootstrap
(2,000 resamples of captures; correlated effects inside one capture are never
treated as independent) and a paired bootstrap for differences; B2/B3 use
Wilson intervals and exact McNemar tests (``benchmarks/stats.py``).
"""

from __future__ import annotations

import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from common import RESULTS  # noqa: E402
from stats import cluster_bootstrap, mcnemar_exact, prf, wilson  # noqa: E402

C = ["#2a78d6", "#eb6834", "#1baf7a", "#8a5cd1"]
INK, MUTED, GRID = "#1b1f24", "#5d6570", "#e3e5e8"
plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED,
    "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True, "legend.frameon": False,
    "savefig.dpi": 130, "savefig.bbox": "tight",
})
METHOD_LABEL = {
    "v01_exact_ref_join_fused": "v0.1-style exact-ref join",
    "pid_nearest_fused": "PID-nearest (same fused input)",
    "revenant_no_fallback": "REVENANT without image fallback",
    "revenant": "REVENANT",
}
ABLATION_LABEL = {
    "revenant": "full engine",
    "revenant_no_fallback": "- image-only fallback rules",
    "revenant_no_image_in_key": "- image in the process key",
    "revenant_no_termination_guard": "- PID-reuse (termination) guard",
    "revenant_no_fusion": "- Sysmon/4688 fusion",
    "pid_nearest_fused": "PID-nearest baseline (reference)",
}
STATS: dict = {}


def load(name):
    p = RESULTS / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _f1(rows, m):
    tp = sum(r[m][0] for r in rows)
    fp = sum(r[m][1] for r in rows)
    hit = sum(r[m][2] for r in rows)
    n = sum(r["n_eval"] for r in rows)
    return prf(tp, fp, hit, n)[2]


def b1_stats(c: dict) -> dict:
    rows = [r for r in c.get("per_capture", []) if r["n_eval"]]
    out: dict = {"captures_with_effects": len(rows), "captures": c["datasets"]}
    if not rows:
        return out
    for m in [k for k in rows[0] if isinstance(rows[0][k], list)]:
        out[m] = {"f1_ci95": cluster_bootstrap(rows, lambda s, m=m: _f1(s, m)),
                  "macro_f1": round(sum(prf(*r[m], r["n_eval"])[2] for r in rows) / len(rows), 4)}
    out["revenant_minus_pid_nearest_fused_f1_ci95"] = cluster_bootstrap(
        rows, lambda s: _f1(s, "revenant") - _f1(s, "pid_nearest_fused"))
    out["revenant_minus_no_fallback_f1_ci95"] = cluster_bootstrap(
        rows, lambda s: _f1(s, "revenant") - _f1(s, "revenant_no_fallback"))
    top3 = sorted(rows, key=lambda r: -r["n_eval"])[:3]
    out["top3_capture_share"] = round(sum(r["n_eval"] for r in top3) / sum(r["n_eval"] for r in rows), 3)
    return out


def fig_edges(d, md):
    corp = [c for c in d["corpora"] if c["evaluable_effects"]]
    for c in corp:
        STATS.setdefault("b1", {})[c["corpus"]] = b1_stats(c)
    methods = list(METHOD_LABEL)
    fig, ax = plt.subplots(figsize=(8.4, 3.6))
    w = 0.2
    for j, m in enumerate(methods):
        xs = [i + (j - 1.5) * w for i in range(len(corp))]
        vals = [c["methods"][m]["f1"] for c in corp]
        cis = [STATS["b1"][c["corpus"]].get(m, {}).get("f1_ci95") for c in corp]
        err = [[max(0, v - ci[0]) if ci else 0 for v, ci in zip(vals, cis)],
               [max(0, ci[1] - v) if ci else 0 for v, ci in zip(vals, cis)]]
        ax.bar(xs, vals, w - 0.03, color=C[j], label=METHOD_LABEL[m], yerr=err, ecolor=MUTED, capsize=2)
        for x, v in zip(xs, vals):
            ax.text(x, min(v, 1.0) + 0.04, f"{v:.2f}", ha="center", va="bottom", fontsize=7, color=INK)
    ax.set_xticks(range(len(corp)), [f"{c['corpus'].replace('otrf_', '')}\n({c['evaluable_effects']:,} effects)"
                                     for c in corp], fontsize=8)
    ax.set_ylim(0, 1.18)
    ax.set_ylabel("F1 vs Sysmon-GUID truth")
    ax.set_title("Causal-edge inference with GUIDs hidden (95% capture-bootstrap CI)", loc="left", color=INK)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=2, fontsize=8)
    fig.savefig(RESULTS / "edges_f1.png")
    plt.close(fig)

    md += ["## B1 - causal edges vs Sysmon GUID ground truth", "",
           "Baselines run on the same fused, shadow-free events REVENANT sees. 95% CIs resample captures "
           "(cluster bootstrap, 2,000 reps); single-capture corpora have no CI.", "",
           "| corpus | captures (with effects) | effects | method | precision | recall | F1 [95% CI] | macro F1 |",
           "|---|---|---|---|---|---|---|---|"]
    for c in corp:
        st = STATS["b1"][c["corpus"]]
        for m in ("v01_exact_ref_join", "v01_exact_ref_join_fused", "pid_nearest", "pid_nearest_fused", "revenant"):
            s = c["methods"][m]
            ci = st.get(m, {}).get("f1_ci95")
            cis = f" [{ci[0]:.3f}, {ci[1]:.3f}]" if ci and st["captures_with_effects"] > 1 else ""
            mf = st.get(m, {}).get("macro_f1")
            md.append(f"| {c['corpus']} | {c['datasets']} ({st['captures_with_effects']}) | {c['evaluable_effects']:,} | "
                      f"{m} | {s['precision']:.3f} | {s['recall']:.3f} | {s['f1']:.3f}{cis} | "
                      f"{mf if mf is not None else '-'} |")
    md.append("")
    md += ["### Ablation (one component removed; F1)", "",
           "| corpus | " + " | ".join(ABLATION_LABEL.values()) + " |", "|---|" + "---|" * len(ABLATION_LABEL)]
    for c in corp:
        md.append(f"| {c['corpus']} | " + " | ".join(f"{c['methods'][k]['f1']:.3f}" for k in ABLATION_LABEL) + " |")
    md.append("")
    for c in corp:
        st = STATS["b1"][c["corpus"]]
        if st["captures_with_effects"] > 1:
            a, b = st["revenant_minus_pid_nearest_fused_f1_ci95"], st["revenant_minus_no_fallback_f1_ci95"]
            md.append(f"- {c['corpus']}: REVENANT - PID-nearest F1 difference 95% CI [{a[0]:+.3f}, {a[1]:+.3f}]; "
                      f"contribution of the fallback rules [{b[0]:+.3f}, {b[1]:+.3f}]; the 3 largest captures hold "
                      f"{st['top3_capture_share']:.0%} of the effects.")
    md.append("")
    md += ["Per effect type (F1, with n):", "", "| corpus | effect | n | PID-nearest (fused) | REVENANT |",
           "|---|---|---|---|---|"]
    for c in corp:
        for t, r in c["by_effect_type"]["revenant"].items():
            b = c["by_effect_type"].get("pid_nearest_fused", c["by_effect_type"]["pid_nearest"])[t]
            md.append(f"| {c['corpus']} | {t} | {r['n_eval']:,} | {b['f1']:.3f} | {r['f1']:.3f} |")
    md.append("")


def fig_calibration(d, md):
    cc = d.get("calibration_cross_corpus")
    if not cc:
        return
    atomic = next(c for c in d["corpora"] if c["corpus"] == "otrf_atomic")
    key = next(k for k in cc if k.endswith("test_otrf_atomic"))
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
    md += ["## Edge-confidence calibration", "",
           "Per-rule constants fitted on one corpus, tested on another. Hand-set confidences were *under*-confident "
           "(accuracy above confidence in every bin). When every test edge is correct (APT29), ECE only measures how "
           "close the constants are to 1, so the atomic test set is the informative direction.", "",
           "| test corpus | fitted on | ECE hand-set | ECE calibrated | Brier calibrated | AUROC | test accuracy |",
           "|---|---|---|---|---|---|---|"]
    for k, v in cc.items():
        test = k.split("_test_")[1]
        fit = k.split("_test_")[0].removeprefix("fit_")
        hs = next(c for c in d["corpora"] if c["corpus"] == test)["revenant_calibration_handset"]
        t = v["test"]
        md.append(f"| {test} | {fit} | {hs['ece']:.3f} | {t['ece']:.3f} | {t.get('brier', '-')} | "
                  f"{t.get('auroc') if t.get('auroc') is not None else 'n/a (all correct)'} | {t.get('accuracy', '-')} |")
    for c in d["corpora"]:
        h = c.get("calibration_heldout_atomic_table")
        if h and h["n"]:
            md.append(f"| {c['corpus']} | otrf_atomic | {c['revenant_calibration_handset']['ece']:.3f} | {h['ece']:.3f} | "
                      f"{h.get('brier', '-')} | {h.get('auroc') if h.get('auroc') is not None else 'n/a (all correct)'} | "
                      f"{h.get('accuracy', '-')} |")
    md += ["", "Story confidence and grades are *not* calibrated: they are a documented, hand-weighted sum "
           "(see Limitations).", ""]


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
           "Every method gets the same event budget (k x the capture's median story size). The story-unit view gives "
           "the flat list exactly as many events as REVENANT's top-k whole stories contain.", "",
           "| method | hit@1 [95% CI] | hit@3 | hit@5 | story-unit hit@1 | hit@3 | hit@5 | reached | median events read |",
           "|---|---|---|---|---|---|---|---|---|"]
    for m, lab in methods:
        r = s[m]
        ci = r["hit@1_ci95"]
        md.append(f"| {lab} | {r['hit@1']:.3f} [{ci[0]:.2f}, {ci[1]:.2f}] | {r['hit@3']:.3f} | {r['hit@5']:.3f} | "
                  f"{r['story_hit@1']:.3f} | {r['story_hit@3']:.3f} | {r['story_hit@5']:.3f} | {r['found']}/{s['captures']} | "
                  f"{r['median_events_to_evidence']} |")
    md += ["", "Paired exact McNemar, REVENANT vs flat suspicion-sorted (discordant captures REVENANT-only / flat-only, p):", ""]
    md.append(", ".join(f"{k}: {v['revenant_only']}/{v['flat_only']}, p={v['mcnemar_p']}" for k, v in t.items()))
    md.append("")
    STATS["b2"] = {"captures": s["captures"], "revenant_vs_flat": t}


def fig_scale(d, md):
    sc = d["rule_engine_scaling"]
    fig, ax = plt.subplots(figsize=(5.6, 3.6))
    for j, (k, lab) in enumerate([("v01_pairwise", f"v0.1 pairwise (slope {sc['loglog_slope_v01']})"),
                                  ("v02_indexed", f"v0.2 indexed (slope {sc['loglog_slope_v02']})")]):
        ax.plot([r["n"] for r in sc[k]], [max(r["seconds"], 1e-3) for r in sc[k]], color=C[j], lw=2,
                marker="o", ms=6, mec="white", mew=1.5, label=lab)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("events (time-ordered prefix of APT29 day 1)")
    ax.set_ylabel("rule inference, seconds")
    ax.set_title("Rule-engine scaling on real events", loc="left", color=INK, fontsize=10)
    ax.legend(fontsize=8)
    fig.savefig(RESULTS / "scaling.png")
    plt.close(fig)
    e = d["end_to_end"]
    stages = ", ".join(f"{k} {v:.1f} s" for k, v in e["stage_s"].items())
    md += ["## B4 - scale (APT29 day 1, full capture)", "",
           f"- {e['events']:,} normalized events from {e['raw_rows']:,} raw rows "
           f"(mapping coverage {e['mapping_coverage']:.1%})",
           f"- analysis of pre-parsed events (JSON parsing excluded; {e['load_s_cached']} s to load the parsed cache): "
           f"{e['analysis_s']} s ({e['events_per_s']:,.0f} events/s); stages: {stages}. Single run on a laptop "
           "with other work running.",
           f"- {e['edges']:,} causal edges, {e['corroborations']:,} cross-artefact corroborations, "
           f"{e['stories']} stories, {e['indicators']} tamper/coverage indicators",
           f"- rule engine log-log slope: v0.1 {sc['loglog_slope_v01']} vs v0.2 {sc['loglog_slope_v02']}; "
           f"v0.1 extrapolated to the full capture: ~{sc['v01_extrapolated_full_capture_s']:,.0f} s", ""]


def af_table(d, md):
    md += ["## B3 - anti-forensics on EVTX-ATTACK-SAMPLES (file level)", "",
           f"{d['readable_files']} readable .evtx files, only {d['positives']} labelled as log/timestamp tampering "
           f"by file name, so every interval is wide. Parser: {d['parser']['records']:,} records; "
           f"{d['parser']['coverage_supported_channels']:.1%} of the {d['parser']['supported_channel_records']:,} records "
           f"in supported channels mapped.", "",
           "| detector | precision [95% CI] | recall [95% CI] | F1 | TP | FP | FN |", "|---|---|---|---|---|---|---|"]
    STATS["b3"] = {}
    for m, lab in [("baseline_1102_104", "1102/104 query (baseline)"), ("revenant", "REVENANT, all indicators"),
                   ("revenant_high_only", "REVENANT, high severity only")]:
        r = d["methods"][m]
        pci, rci = wilson(r["tp"], r["tp"] + r["fp"]), wilson(r["tp"], r["tp"] + r["fn"])
        STATS["b3"][m] = {"precision_ci95": pci, "recall_ci95": rci}
        md.append(f"| {lab} | {r['precision']:.3f} [{pci[0]:.2f}, {pci[1]:.2f}] | {r['recall']:.3f} "
                  f"[{rci[0]:.2f}, {rci[1]:.2f}] | {r['f1']:.3f} | {r['tp']} | {r['fp']} | {r['fn']} |")
    rows = d.get("rows") or []
    if rows and "revenant" in rows[0]:
        b = sum(r["revenant"] and not r["baseline_1102_104"] for r in rows if r.get("positive"))
        c = sum(r["baseline_1102_104"] and not r["revenant"] for r in rows if r.get("positive"))
        md.append(f"\nPaired exact McNemar on the positives: p={mcnemar_exact(b, c)}.")
    md += ["", f"Missed positives: {', '.join(d['missed_positives']) or 'none'}", ""]


def atlas_table(d, md):
    s = d["paper_vs_spreadsheet"]
    md += ["## C - ATLAS reproduction (Alsaheel et al., USENIX Security 2021)", "",
           "| level | paper | recomputed from the released per-attack counts (macro) | pooled (micro) |",
           "|---|---|---|---|"]
    for lvl in ("entity", "event"):
        p, m, mi = d["paper"][lvl], s[f"{lvl}_macro"], s[f"{lvl}_micro"]
        md.append(f"| {lvl} P / R / F1 | {p['precision']:.4f} / {p['recall']:.4f} / {p['f1']:.4f} | "
                  f"{m['precision']:.4f} / {m['recall']:.4f} / {m['f1']:.4f} | "
                  f"{mi['precision']:.4f} / {mi['recall']:.4f} / {mi['f1']:.4f} |")
    chk = d.get("event_totals_match_spreadsheet", {})
    if chk:
        ok = sum(v["match"] for v in chk.values())
        md.append(f"\nReleased model outputs contain exactly the spreadsheet's event totals for {ok}/{len(chk)} attacks.")
    md.append("")


def main() -> int:
    md = ["<!-- results:start -->",
          "Generated by `python benchmarks/make_figures.py` from `results/*.json`; CIs are 95%.", ""]
    if (d := load("edges.json")):
        fig_edges(d, md)
        fig_calibration(d, md)
    if (d := load("stories.json")):
        fig_stories(d, md)
    if (d := load("antiforensics.json")):
        af_table(d, md)
    if (d := load("scale.json")):
        fig_scale(d, md)
    if (d := load("atlas_repro.json")):
        atlas_table(d, md)
    md.append("<!-- results:end -->")
    (RESULTS / "RESULTS.md").write_text("# REVENANT benchmark results\n\n" + "\n".join(md) + "\n", encoding="utf-8")
    (RESULTS / "stats.json").write_text(json.dumps(STATS, indent=1) + "\n", encoding="utf-8")
    print("[results] RESULTS.md, stats.json + figures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
