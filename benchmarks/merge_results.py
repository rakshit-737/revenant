"""Assemble the ``bench-extended`` job outputs into ``results/`` (run by the workflow's combine job).

The workflow splits the corpus benchmarks over jobs (``main``: B1 on four
corpora with the calibration refit, B2, B3, B3b; ``day2``: B1 on APT29 day 2;
``scale``: B4). This script merges the two B1 files into ``edges.json``,
copies the others under their canonical names and stamps every file with the
combine job's provenance, so each committed result names the run that made it.

Usage::

    python benchmarks/merge_results.py --artifacts DIR [--results results]
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from stats import provenance

ROOT = Path(__file__).resolve().parents[1]
COPY = {"stories_ci.json": "stories.json", "antiforensics_ci.json": "antiforensics.json",
        "antiforensics_b3b_ci.json": "antiforensics_b3b.json", "scale_ci.json": "scale.json"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--artifacts", type=Path, required=True)
    ap.add_argument("--results", type=Path, default=ROOT / "results")
    a = ap.parse_args(argv)
    src = provenance("bench-extended")
    files = {p.name: p for p in a.artifacts.rglob("*.json")}
    a.results.mkdir(parents=True, exist_ok=True)
    if "edges_ci_main.json" in files:
        edges = json.loads(files["edges_ci_main.json"].read_text(encoding="utf-8"))
        if "edges_ci_day2.json" in files:
            day2 = json.loads(files["edges_ci_day2.json"].read_text(encoding="utf-8"))
            edges["corpora"] += day2["corpora"]
            edges["runtime_s"] = round(edges.get("runtime_s", 0) + day2.get("runtime_s", 0), 1)
        edges["source"] = src
        (a.results / "edges.json").write_text(json.dumps(edges, indent=2, default=str) + "\n", encoding="utf-8")
        print("edges.json:", [c["corpus"] for c in edges["corpora"]])
    for name, dst in COPY.items():
        if name in files:
            d = json.loads(files[name].read_text(encoding="utf-8"))
            d["source"] = src
            (a.results / dst).write_text(json.dumps(d, indent=2, default=str) + "\n", encoding="utf-8")
            print(dst)
    if "rule_calibration.json" in files:
        shutil.copy2(files["rule_calibration.json"], ROOT / "src" / "revenant" / "data" / "rule_calibration.json")
        print("rule_calibration.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
