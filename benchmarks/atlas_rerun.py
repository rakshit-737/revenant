"""Re-run ATLAS's released ``model.h5`` and compare the fresh outputs with the released ones.

The released ``eval_*.json`` of every experiment holds, in this order: the
authors' *hand-cleaned* predicted entities (field 0), the malicious labels,
the symptom, the candidate graph words, the model's 0/1 prediction and
probability for each word, the test log lines and the dataset name.
``atlas.py`` in testing mode (``DO_TRAINING = False``) regenerates fields 1-7
from ``output/model.h5`` and the released test graph, and writes field 0 as an
empty list -- the cleaning is a manual step (ATLAS README).

Subcommands (run by ``.github/workflows/atlas-repro.yml``, one attack per job):

``stage``
    For each test graph that has a released ``eval_*.json`` next to it, copy
    exactly the inputs ``atlas.py`` reads in testing mode (``atlas.py``,
    ``output/model.h5``, the ``seq_graph_testing_*`` graph, its
    ``testing_preprocessed_logs_*`` file and ``testing_logs/``) into a scratch
    folder and force ``DO_TRAINING = False``.
``score``
    After the workflow ran ``atlas.py`` in every scratch folder (TensorFlow 2.3
    container, no network): diff each fresh ``eval_*.json`` against the
    released one (graph words, predicted words, probabilities), and write two
    ``evaluate.py`` folders per attack that score the model's *raw* predicted
    words (no manual cleaning) -- one for the fresh re-run, one for the release.

Usage::

    python benchmarks/atlas_rerun.py stage --root DIR --attack S2 --out DIR
    python benchmarks/atlas_rerun.py score --root DIR --attack S2 --staged DIR --out DIR --summary FILE
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

NO_PREDICTION = "<atlas:no-predicted-word>"  # evaluate.py exits on an empty list; this matches nothing
_DO_TRAINING = re.compile(r"^DO_TRAINING\s*=.*$", re.MULTILINE)


def experiment_folders(root: Path, attack: str) -> list[tuple[str, Path]]:
    """(tag, folder) of every experiment folder of one attack: S2 -> [S2]; M1 -> [M1_h1, M1_h2]."""
    base = root / "paper_experiments" / attack
    if attack.startswith("M"):
        return [(f"{attack}_{h}", base / h) for h in ("h1", "h2") if (base / h).is_dir()]
    return [(attack, base)] if base.is_dir() else []


def test_graphs(folder: Path) -> list[str]:
    """Names X of ``output/seq_graph_testing_X`` graphs that have a released ``eval_X.json`` beside them."""
    out = []
    for g in sorted((folder / "output").glob("seq_graph_testing_*.dot.txt")):
        if (folder / "output" / f"eval_{g.name}.json").exists():
            out.append(g.name)
    return out


def stage(root: Path, attack: str, out: Path) -> int:
    staged = []
    for tag, folder in experiment_folders(root, attack):
        for graph in test_graphs(folder):
            logs = "output/" + graph[len("seq_graph_"):-len(".dot.txt")]
            dst = out / f"{tag}__{graph}"
            (dst / "output").mkdir(parents=True, exist_ok=True)
            src = (folder / "atlas.py").read_text(encoding="utf-8", errors="replace")
            m = _DO_TRAINING.search(src)
            (dst / "atlas.py").write_text(_DO_TRAINING.sub("DO_TRAINING = False", src, count=1), encoding="utf-8")
            for rel in ("output/model.h5", f"output/{graph}", logs):
                shutil.copy2(folder / rel, dst / rel)
            shutil.copytree(folder / "testing_logs", dst / "testing_logs", dirs_exist_ok=True)
            staged.append({"dir": dst.name, "experiment": tag, "graph": graph,
                           "do_training_line": m.group(0) if m else None})
    out.mkdir(parents=True, exist_ok=True)
    (out / "staged.json").write_text(json.dumps(staged, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(staged, indent=1))
    return 0 if staged else 1


def _sha(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj).encode("utf-8")).hexdigest()[:16]


def _predicted(d: list) -> list[str]:
    return sorted({w for w, p in zip(d[3], d[4]) if p == 1})


def diff(fresh: list, released: list) -> dict:
    """Compare a fresh atlas.py output with the released file of the same name."""
    fw, rw = fresh[3], released[3]
    same_words = fw == rw
    fp_, rp_ = set(_predicted(fresh)), set(_predicted(released))
    out = {
        "symptom": fresh[2], "released_symptom": released[2],
        "graph_words": len(fw), "released_graph_words": len(rw), "graph_words_identical": same_words,
        "lines": len(fresh[6]), "lines_identical": _sha(fresh[6]) == _sha(released[6]),
        "predicted_words": sorted(fp_), "released_predicted_words": sorted(rp_),
        "predicted_identical": fp_ == rp_, "only_rerun": sorted(fp_ - rp_), "only_released": sorted(rp_ - fp_),
        "released_cleaned_entities": released[0],
    }
    if same_words:
        out["prediction_flips"] = sum(int(a) != int(b) for a, b in zip(fresh[4], released[4]))
        out["max_abs_probability_difference"] = round(max((abs(float(a) - float(b))
                                                           for a, b in zip(fresh[5], released[5])), default=0.0), 6)
    return out


def _write_raw(d: list, dst: Path) -> None:
    d = list(d)
    d[0] = _predicted(d) or [NO_PREDICTION]
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(d), encoding="utf-8")


def score(root: Path, attack: str, staged_dir: Path, out: Path, summary: Path) -> int:
    staged = json.loads((staged_dir / "staged.json").read_text(encoding="utf-8"))
    folders = dict(experiment_folders(root, attack))
    res: dict = {"attack": attack, "runs": {}, "failed": []}
    ok_files: dict[str, tuple[Path, Path]] = {}
    for s in staged:
        fresh_p = staged_dir / s["dir"] / "output" / f"eval_{s['graph']}.json"
        released_p = folders[s["experiment"]] / "output" / f"eval_{s['graph']}.json"
        key = f"{s['experiment']}:{s['graph']}"
        if not fresh_p.exists():
            res["failed"].append(key)
            res["runs"][key] = {"ok": False, "error": "atlas.py wrote no eval_*.json (see its log)"}
            continue
        fresh = json.loads(fresh_p.read_text(encoding="utf-8", errors="replace"))
        released = json.loads(released_p.read_text(encoding="utf-8", errors="replace"))
        res["runs"][key] = {"ok": True, "experiment": s["experiment"], **diff(fresh, released)}
        ok_files[s["graph"]] = (fresh_p, released_p)
    # scoring folder: the experiment whose evaluate.py scores the whole attack (M: h2 holds both hosts)
    score_tag = f"{attack}_h2" if attack.startswith("M") else attack
    evaluate = folders[score_tag] / "evaluate.py" if score_tag in folders else None
    wanted = test_graphs(folders[score_tag]) if score_tag in folders else []
    if attack.startswith("M") and f"{attack}_h1" in folders:
        wanted = sorted(set(wanted) | set(test_graphs(folders[f"{attack}_h1"])))
    res["scored_graphs"] = wanted
    res["complete"] = bool(wanted) and all(g in ok_files for g in wanted)
    if res["complete"] and evaluate is not None:
        for variant, idx in (("rerun_raw", 0), ("released_raw", 1)):
            dst = out / variant / f"{attack[0]}-{attack[1:]}"  # folder named like the attack id, e.g. S-2
            for g in wanted:
                p = ok_files[g][idx]
                _write_raw(json.loads(p.read_text(encoding="utf-8", errors="replace")), dst / "output" / p.name)
            shutil.copy2(evaluate, dst / "evaluate.py")
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k != "runs"}, indent=1))
    for k, v in res["runs"].items():
        print(k, {x: v.get(x) for x in ("ok", "graph_words_identical", "predicted_identical", "prediction_flips",
                                       "max_abs_probability_difference")})
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stage")
    s.add_argument("--root", type=Path, required=True)
    s.add_argument("--attack", required=True)
    s.add_argument("--out", type=Path, required=True)
    c = sub.add_parser("score")
    c.add_argument("--root", type=Path, required=True)
    c.add_argument("--attack", required=True)
    c.add_argument("--staged", type=Path, required=True)
    c.add_argument("--out", type=Path, required=True)
    c.add_argument("--summary", type=Path, required=True)
    a = ap.parse_args(argv)
    if a.cmd == "stage":
        return stage(a.root, a.attack, a.out)
    return score(a.root, a.attack, a.staged, a.out, a.summary)


if __name__ == "__main__":
    sys.exit(main())
