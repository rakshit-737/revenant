"""Render README figures + results/RESULTS.md from results/*.json."""

from __future__ import annotations

import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from common import RESULTS  # noqa: E402

# validated default categorical slots (fixed order, never cycled)
C = ["#2a78d6", "#eb6834", "#1baf7a"]
INK, MUTED, GRID = "#1b1f24", "#5d6570", "#e3e5e8"
plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED,
    "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.8, "axes.axisbelow": True, "legend.frameon": False,
    "savefig.dpi": 130, "savefig.bbox": "tight",
})
METHOD_LABEL = {"v01_exact_ref_join": "v0.1 exact-ref join", "pid_nearest": "PID-nearest baseline",
                "revenant": "REVENANT v0.2"}


def load(name):
    p = RESULTS / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def fig_edges(d, md):
    corp = d["corpora"]
    methods = list(METHOD_LABEL)
    fig, ax = plt.subplots(figsize=(7, 3.4))
    w = 0.26
    for j, m in enumerate(methods):
        xs = [i + (j - 1) * w for i in range(len(corp))]
        vals = [c["methods"][m]["f1"] for c in corp]
        ax.bar(xs, vals, w - 0.03, color=C[j], label=METHOD_LABEL[m])
        for x, v in zip(xs, vals):
            ax.text(x, v + 0.015, f"{v:.2f}", ha="center", va="bottom", fontsize=8, color=INK)
    ax.set_xticks(range(len(corp)), [f"{c['corpus']}\n({c['evaluable_effects']:,} effects)" for c in corp])
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("F1 vs Sysmon-GUID truth")
    ax.set_title("Causal-edge inference with GUIDs hidden", loc="left", color=INK)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=3)
    fig.savefig(RESULTS / "edges_f1.png")
    plt.close(fig)
    md += ["## B1 - causal edges vs Sysmon GUID ground truth", "",
           "| corpus | method | precision | recall | F1 | false-edge rate |", "|---|---|---|---|---|---|"]
    for c in corp:
        for m in methods:
            s = c["methods"][m]
            md.append(f"| {c['corpus']} | {METHOD_LABEL[m]} | {s['precision']:.3f} | {s['recall']:.3f} | "
                      f"{s['f1']:.3f} | {s['false_edge_rate']:.3f} |")
    md.append("")
    md += ["Per effect type (REVENANT vs PID-nearest, F1):", "", "| corpus | effect | n | PID-nearest | REVENANT |",
           "|---|---|---|---|---|"]
    for c in corp:
        for t, r in c["by_effect_type"]["revenant"].items():
            b = c["by_effect_type"]["pid_nearest"][t]
            md.append(f"| {c['corpus']} | {t} | {r['n_eval']} | {b['f1']:.3f} | {r['f1']:.3f} |")
    md.append("")


def fig_calibration(d, md):
    cc = d.get("calibration_cross_corpus")
    if not cc:
        return
    apt = next(c for c in d["corpora"] if "apt29" in c["corpus"])
    key = next(k for k in cc if k.endswith("apt29_day1"))
    fig, ax = plt.subplots(figsize=(4.6, 4))
    ax.plot([0, 1], [0, 1], color=MUTED, lw=1, ls="--", label="perfect calibration")
    for j, (label, cal) in enumerate([("hand-set confidences", apt["revenant_calibration_handset"]),
                                      ("calibrated on atomic", cc[key]["test"])]):
        xs = [b["mean_confidence"] for b in cal["bins"]]
        ys = [b["accuracy"] for b in cal["bins"]]
        ax.plot(xs, ys, color=C[j], lw=2, marker="o", ms=6, mec="white", mew=1.5,
                label=f"{label} (ECE {cal['ece']:.3f})")
    ax.set_xlim(0, 1.02)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("mean edge confidence (bin)")
    ax.set_ylabel("fraction of edges correct")
    ax.set_title("Edge-confidence reliability, APT29 (held out)", loc="left", color=INK, fontsize=10)
    ax.legend(loc="lower right", fontsize=8)
    fig.savefig(RESULTS / "calibration.png")
    plt.close(fig)
    md += ["## Edge-confidence calibration (ECE, lower is better)", "", "| evaluated on | hand-set | cross-corpus calibrated |",
           "|---|---|---|"]
    for c in d["corpora"]:
        k = next(k for k in cc if k.endswith(c["corpus"]))
        md.append(f"| {c['corpus']} | {c['revenant_calibration_handset']['ece']:.3f} | {cc[k]['test']['ece']:.3f} "
                  f"(fit on the other corpus) |")
    md.append("")


def fig_stories(d, md):
    s = d["all"]
    methods = [("chronological", "chronological timeline"), ("flat_suspicion", "flat, suspicion-sorted"),
               ("revenant", "REVENANT stories")]
    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    ks = [1, 3, 5]
    for j, (m, lab) in enumerate(methods):
        ys = [s[m][f"hit@{k}"] for k in ks]
        ax.plot(ks, ys, color=C[j], lw=2, marker="o", ms=7, mec="white", mew=1.5, label=lab)
        ax.annotate(f"{ys[-1]:.2f}", (ks[-1], ys[-1]), xytext=(6, 0), textcoords="offset points",
                    va="center", fontsize=8, color=INK)
    ax.set_xticks(ks, [f"top-{k}" for k in ks])
    ax.set_ylim(-0.02, 1)
    ax.set_xlim(0.8, 5.6)
    ax.set_ylabel("captures with labelled technique found")
    ax.set_title(f"Reaching the labelled ATT&CK technique ({s['captures']} OTRF captures)", loc="left",
                 color=INK, fontsize=10)
    ax.legend(loc="upper left", fontsize=8)
    fig.savefig(RESULTS / "stories_hitk.png")
    plt.close(fig)
    md += ["## B2 - story ranking vs flat timelines (OTRF atomic, ATT&CK labels from metadata)", "",
           "| method | hit@1 | hit@3 | hit@5 | captures reached | median events read | mean events read |",
           "|---|---|---|---|---|---|---|"]
    for m, lab in methods:
        r = s[m]
        md.append(f"| {lab} | {r['hit@1']:.3f} | {r['hit@3']:.3f} | {r['hit@5']:.3f} | {r['found']}/{s['captures']} | "
                  f"{r['median_events_to_evidence']} | {r['mean_events_to_evidence']} |")
    md.append("")


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
    md += ["## B4 - scale (APT29 day 1, full capture)", "",
           f"- {e['events']:,} normalized events from {e['raw_rows']:,} raw rows "
           f"(mapping coverage {e['mapping_coverage']:.1%})",
           f"- analysis {e['analysis_s']} s ({e['events_per_s']:,.0f} events/s); stages: {e['stage_s']}",
           f"- {e['edges']:,} causal edges, {e['corroborations']:,} cross-artefact corroborations, "
           f"{e['stories']} stories, {e['indicators']} tamper/coverage indicators",
           f"- rule engine log-log slope: v0.1 {sc['loglog_slope_v01']} vs v0.2 {sc['loglog_slope_v02']}; "
           f"v0.1 extrapolated to the full capture: ~{sc['v01_extrapolated_full_capture_s']:,.0f} s", ""]


def af_table(d, md):
    md += ["## B3 - anti-forensics on EVTX-ATTACK-SAMPLES (file level)", "",
           f"{d['readable_files']} readable .evtx files, {d['positives']} labelled as log/timestamp tampering "
           f"by file name. Parser: {d['parser']['records']:,} records; {d['parser']['coverage_supported_channels']:.1%} of "
           f"the {d['parser']['supported_channel_records']:,} records in supported channels mapped "
           f"({d['parser']['coverage']:.1%} of all records, most of the rest being one ETW RPC trace); "
           f"{d['parser']['records_per_s']:,.0f} records/s (python-evtx).", "",
           "| detector | precision | recall | F1 | TP | FP | FN |", "|---|---|---|---|---|---|---|"]
    for m, lab in [("baseline_1102_104", "1102/104 query (baseline)"), ("revenant", "REVENANT, all indicators"),
                   ("revenant_high_only", "REVENANT, high severity only")]:
        r = d["methods"][m]
        md.append(f"| {lab} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} | {r['tp']} | {r['fp']} | {r['fn']} |")
    md += ["", f"Missed positives: {', '.join(d['missed_positives']) or 'none'}", ""]


def main() -> int:
    md = ["# REVENANT benchmark results", "",
          "Generated by `python benchmarks/make_figures.py` from `results/*.json`. Do not edit by hand.", ""]
    if (d := load("edges.json")):
        fig_edges(d, md)
        fig_calibration(d, md)
    if (d := load("stories.json")):
        fig_stories(d, md)
    if (d := load("antiforensics.json")):
        af_table(d, md)
    if (d := load("scale.json")):
        fig_scale(d, md)
    (RESULTS / "RESULTS.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("[results] RESULTS.md + figures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
