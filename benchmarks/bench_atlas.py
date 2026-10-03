"""C2 -- REVENANT scored under the ATLAS protocol (Alsaheel et al., USENIX Security 2021).

ATLAS evaluates attack investigation per attack: start from one known *symptom*
entity, return the entities you believe belong to the attack, and let the
authors' ``evaluate.py`` count them against the malicious-entity labels, both
per entity (unique graph words) and per event (log lines). This script puts
REVENANT through exactly that harness:

1. For every attack (S-1..S-4 single host, M-1..M-6 two hosts) read the test
   host's preprocessed log from the released ``eval_*.json`` (field 6, the same
   lines ``evaluate.py`` scores) and parse it with `revenant.parsers.atlas`,
   which strips ATLAS's ``-LA+``/``-LA-`` ground-truth suffix first.
2. Run the normal REVENANT engine (fusion, causal rules, anti-forensics, ATT&CK
   tags) on that host.
3. Seed a story with the symptom entity the authors' code used for that host
   (``atlas.py`` sets ``user_artifact = malicious_labels[0]``, recorded as
   field 2 of the released ``eval_*.json``): every event that names the symptom
   (or an address a symptom domain resolved to) is a seed, and
   `revenant.stories.seeded_story` returns the story around the seeds.
4. Map the story's entities to ATLAS label strings
   (`revenant.parsers.atlas.entity_labels`, docs/atlas-mapping.md) and write
   them as field 0 ("cleaned predicted entities") of a copy of the released
   ``eval_*.json``. Fields 3-5 (graph words, model predictions and
   probabilities) are replaced by REVENANT's own 0/1 decision so nothing of
   ATLAS's model leaks into the score.
5. ``prepare`` writes one folder per (method, attack) laid out like the
   authors' experiment folders (multi-host attacks hold both hosts' files, as
   ATLAS's README prescribes for the h2 folder); the workflow runs the
   authors' ``evaluate.py`` in each, offline, in the Python 3.7 container;
   ``collect`` parses the printed counts and computes the statistics.

Methods: ``revenant`` (default story: cap of 200 events per story root,
benign non-process leaves omitted), ``revenant_uncapped`` (no cap),
``backtracker`` (BackTracker-style reachability: every causal ancestor and
descendant of the seeds, unpruned) and ``symptom_only`` (the symptom and its
DNS aliases alone).

Usage::

    python benchmarks/bench_atlas.py prepare --root DIR --out DIR [--only S2 M1]
    python benchmarks/bench_atlas.py collect --out DIR --atlas-logs DIR [--results results/atlas_revenant.json]
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from stats import cluster_bootstrap, mcnemar_exact, provenance, wilson  # noqa: E402

ATTACKS = [f"S-{i}" for i in range(1, 5)] + [f"M-{i}" for i in range(1, 7)]
METHODS = ("revenant", "revenant_uncapped", "backtracker", "symptom_only")
NO_PREDICTION = "<revenant:no-prediction>"  # evaluate.py exits on an empty list; this matches nothing
# Table 4 (p. 3016) "Symptom entity" column, for the record
TABLE4_SYMPTOM = {"S-1": "malicious host", "S-2": "leaked file", "S-3": "malicious host", "S-4": "leaked file",
                  "M-1": "leaked file", "M-2": "leaked file", "M-3": "malicious file", "M-4": "malicious file",
                  "M-5": "malicious host", "M-6": "malicious host"}
BOOT_REPS, BOOT_SEED = 10_000, 7


def experiment_dir(root: Path, aid: str) -> Path:
    """The authors' folder whose ``evaluate.py`` scores the whole attack (h2 holds both hosts)."""
    kind, n = aid.split("-")
    base = root / "paper_experiments" / f"{kind}{n}"
    return base / "h2" if kind == "M" else base


def eval_files(expdir: Path) -> list[Path]:
    """Released ``eval_*.json`` files of one experiment folder (macOS archive junk skipped)."""
    return sorted(p for p in (expdir / "output").glob("eval_*.json") if "__MACOSX" not in p.parts)


def host_name(dataset: str, aid: str) -> str:
    m = re.search(r"_(h\d)$", dataset)
    return m.group(1) if m else aid.lower().replace("-", "")


def analyse_host(path: Path, aid: str) -> tuple[dict, dict[str, set[str]]]:
    """Run REVENANT on one released test log; return (metadata, method -> predicted label set)."""
    from revenant.parsers.atlas import entity_labels, iter_records, local_addresses, records_to_events, seed_events
    from revenant.parsers.otrf import LoadStats
    from revenant.pipeline import analyze_events
    from revenant.stories import StoryConfig, seeded_story

    d = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    symptom, dataset, lines = str(d[2]).strip().lower(), d[7], d[6]
    host = host_name(dataset, aid)
    t0 = time.perf_counter()
    st = LoadStats()
    records = list(iter_records(lines, st))
    local = local_addresses(records)
    events = records_to_events(records, host=host, stats=st)
    del d, lines, records
    t_parse = time.perf_counter() - t0
    t0 = time.perf_counter()
    a = analyze_events(events, chains=False)
    t_engine = time.perf_counter() - t0
    g = a.graph
    visible = [e for e in g.events if e.event_id not in g.shadowed]
    seeds, aliases = seed_events(visible, symptom, local)

    def labels(ids) -> set[str]:
        out: set[str] = set()
        for i in ids:
            ev = g.get_event(i)
            if ev is not None:
                out |= entity_labels(ev, local)
        return out

    preds: dict[str, set[str]] = {}
    sizes: dict[str, int] = {}
    for name, cap in (("revenant", None), ("revenant_uncapped", 10**9)):
        cfg = StoryConfig() if cap is None else StoryConfig(max_events=cap)
        story = seeded_story(g, seeds, a.indicators, cfg, a.tags)
        ids = story.event_ids if story else []
        preds[name], sizes[name] = labels(ids), len(ids)
    reach: set[str] = set(seeds)
    for s in seeds:
        reach |= g.ancestors(s) | g.descendants(s)
    preds["backtracker"], sizes["backtracker"] = labels(reach), len(reach)
    preds["symptom_only"], sizes["symptom_only"] = ({symptom, *aliases} if seeds else set()), len(seeds)
    meta = {
        "dataset": dataset, "host": host, "symptom": symptom, "dns_aliases": aliases, "local_addresses": sorted(local),
        "lines": st.rows, "lines_mapped": st.mapped, "events": len(events), "edges": len(g.edges),
        "seeds": len(seeds), "story_events": sizes, "predicted": {k: sorted(v) for k, v in preds.items()},
        "seconds": {"parse": round(t_parse, 1), "engine": round(t_engine, 1)},
    }
    return meta, preds


def write_eval(src: Path, dst: Path, predicted: set[str]) -> None:
    """Copy a released eval_*.json with field 0 = REVENANT's labels and fields 4-5 = its 0/1 decision."""
    d = json.loads(src.read_text(encoding="utf-8", errors="replace"))
    pred = sorted(predicted) or [NO_PREDICTION]
    flags = [1.0 if any(p in w for p in pred) else 0.0 for w in d[3]]
    d[0], d[4], d[5] = pred, flags, list(flags)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(d), encoding="utf-8")


def prepare(root: Path, out: Path, only: list[str] | None) -> int:
    meta: dict = {"attacks": {}}
    for aid in ATTACKS:
        if only and aid.replace("-", "") not in only:
            continue
        exp = experiment_dir(root, aid)
        files = eval_files(exp)
        if not files:
            print(f"[skip] {aid}: no eval_*.json under {exp}", file=sys.stderr)
            continue
        hosts = []
        for f in files:
            m, preds = analyse_host(f, aid)
            hosts.append(m)
            for method in METHODS:
                write_eval(f, out / method / aid / "output" / f.name, preds[method])
            print(aid, m["host"], "symptom", m["symptom"], "seeds", m["seeds"], "events", m["events"],
                  {k: len(v) for k, v in preds.items()}, m["seconds"], flush=True)
        for method in METHODS:
            shutil.copy2(exp / "evaluate.py", out / method / aid / "evaluate.py")
        meta["attacks"][aid] = {"experiment": exp.relative_to(root / "paper_experiments").as_posix(),
                                "table4_symptom_type": TABLE4_SYMPTOM[aid], "hosts": hosts}
    out.mkdir(parents=True, exist_ok=True)
    name = f"meta_{'_'.join(only)}.json" if only else "meta.json"
    (out / name).write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
    return 0


# ----------------------------------------------------------------- collect
def _prf(c: dict) -> dict[str, float]:
    tp, fp, fn = c["tp"], c["fp"], c["fn"]
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0}


def _r(x: float) -> float:
    return round(x, 4)


def summarise(per: dict[str, dict]) -> dict:
    """Macro, pooled (Wilson) and bootstrap-over-attacks statistics for one method."""
    out: dict = {"n_attacks": len(per)}
    rows = list(per.values())
    for lvl in ("entity", "event"):
        prfs = [_prf(v[lvl]) for v in rows]
        out[f"{lvl}_macro"] = {m: _r(sum(p[m] for p in prfs) / len(prfs)) for m in ("precision", "recall", "f1")}
        tot = {k: sum(v[lvl][k] for v in rows) for k in ("tp", "fp", "fn", "tn")}
        out[f"{lvl}_pooled"] = {**tot, **{m: _r(x) for m, x in _prf(tot).items()},
                                "precision_wilson95": wilson(tot["tp"], tot["tp"] + tot["fp"]),
                                "recall_wilson95": wilson(tot["tp"], tot["tp"] + tot["fn"])}
        out[f"{lvl}_macro_f1_bootstrap95"] = cluster_bootstrap(
            rows, lambda s, lvl=lvl: sum(_prf(v[lvl])["f1"] for v in s) / len(s), reps=BOOT_REPS, seed=BOOT_SEED)
    return out


def paired(a: dict[str, dict], b: dict[str, dict], lvl: str) -> dict:
    """Per-attack F1 difference a - b: bootstrap CI over attacks and an exact sign test."""
    keys = sorted(set(a) & set(b))
    diffs = [_prf(a[k][lvl])["f1"] - _prf(b[k][lvl])["f1"] for k in keys]
    better, worse = sum(d > 1e-12 for d in diffs), sum(d < -1e-12 for d in diffs)
    rows = list(zip(keys, diffs))
    return {"n": len(keys), "mean_f1_difference": _r(sum(diffs) / len(diffs)) if diffs else None,
            "bootstrap95": cluster_bootstrap(rows, lambda s: sum(d for _, d in s) / len(s), reps=BOOT_REPS,
                                             seed=BOOT_SEED) if rows else None,
            "a_better": better, "b_better": worse, "ties": len(diffs) - better - worse,
            "sign_test_p": mcnemar_exact(better, worse)}


def collect(out: Path, atlas_logs: Path | None, results: Path) -> int:
    from atlas_repro import eval_logs

    meta: dict = {"attacks": {}}
    for f in sorted(out.glob("meta*.json")):  # one per attack when the workflow runs attacks in parallel
        meta["attacks"].update(json.loads(f.read_text(encoding="utf-8"))["attacks"])
    meta["attacks"] = {k: meta["attacks"][k] for k in ATTACKS if k in meta["attacks"]}
    logs = eval_logs(out / "logs")
    res: dict = {
        "benchmark": "revenant_under_atlas_protocol",
        "protocol": {
            "symptom": "per host, the first line of malicious_labels.txt, as the authors' atlas.py sets "
                       "user_artifact (field 2 of the released eval_*.json)",
            "scoring": "the authors' evaluate.py from each attack's experiment folder, run offline in python:3.7; "
                       "multi-host attacks are scored in one folder holding both hosts' files (ATLAS README)",
            "mapping": "docs/atlas-mapping.md (revenant.parsers.atlas.entity_labels)",
            "labels_read_by_revenant": False,
            "atlas_outputs_hand_cleaned": True,
            "note": "ATLAS's released predictions (field 0) were cleaned by hand before scoring (ATLAS README: "
                    "'manual cleaning'); REVENANT's are produced automatically.",
        },
        "attacks": meta["attacks"],
        "methods": {},
        "bootstrap": {"reps": BOOT_REPS, "seed": BOOT_SEED, "unit": "attack"},
        "source": provenance("atlas-repro"),
    }
    per_method: dict[str, dict[str, dict]] = {}
    missing = []
    for method in METHODS:
        per: dict[str, dict] = {}
        for aid in meta["attacks"]:
            c = logs.get(f"{method}_{aid}", {}).get("counts", {})
            if set(c) == {"entity", "event"}:
                per[aid] = c
            else:
                missing.append(f"{method}_{aid}")
        per_method[method] = per
        res["methods"][method] = {"per_attack": {k: {lvl: {**v[lvl], **{m: _r(x) for m, x in _prf(v[lvl]).items()}}
                                                     for lvl in ("entity", "event")} for k, v in per.items()},
                                  **(summarise(per) if per else {"n_attacks": 0})}
    if atlas_logs and atlas_logs.is_dir():
        alog = eval_logs(atlas_logs)
        pick = {f"S-{i}": f"S{i}" for i in range(1, 5)} | {f"M-{i}": f"M{i}_h2" for i in range(1, 7)}
        atlas = {aid: alog[e]["counts"] for aid, e in pick.items()
                 if set(alog.get(e, {}).get("counts", {})) == {"entity", "event"}}
        res["methods"]["atlas_released"] = {
            "note": "ATLAS's released, hand-cleaned predictions scored by the same evaluate.py (atlas_repro.json)",
            "per_attack": {k: {lvl: {**v[lvl], **{m: _r(x) for m, x in _prf(v[lvl]).items()}}
                               for lvl in ("entity", "event")} for k, v in atlas.items()},
            **(summarise(atlas) if atlas else {"n_attacks": 0})}
        res["paired_vs_atlas"] = {m: {lvl: paired(per_method[m], atlas, lvl) for lvl in ("entity", "event")}
                                  for m in METHODS if per_method[m]}
    res["paired_revenant_vs_backtracker"] = {lvl: paired(per_method["revenant"], per_method["backtracker"], lvl)
                                             for lvl in ("entity", "event")}
    res["missing_runs"] = missing
    results.parent.mkdir(parents=True, exist_ok=True)
    results.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    for m, v in res["methods"].items():
        if v.get("n_attacks"):
            print(f"{m:18s} n={v['n_attacks']} entity macro {v['entity_macro']} event macro {v['event_macro']}")
    print("missing:", missing or "none")
    n_expected = len(meta["attacks"])
    return 0 if not missing and all(len(per_method[m]) == n_expected for m in METHODS) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare", help="analyse every attack and write evaluate.py folders")
    p.add_argument("--root", type=Path, required=True, help="download_atlas.py destination (extracted)")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--only", nargs="*", help="attack ids such as S2 M1")
    c = sub.add_parser("collect", help="parse evaluate.py logs into results JSON")
    c.add_argument("--out", type=Path, required=True)
    c.add_argument("--atlas-logs", type=Path, help="eval_logs of the authors' outputs (atlas-repro step)")
    c.add_argument("--results", type=Path, default=ROOT / "results" / "atlas_revenant.json")
    a = ap.parse_args(argv)
    if a.cmd == "prepare":
        return prepare(a.root, a.out, a.only)
    return collect(a.out, a.atlas_logs, a.results)


if __name__ == "__main__":
    raise SystemExit(main())
